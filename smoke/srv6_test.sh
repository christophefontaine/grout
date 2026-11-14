#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Olivier Gournet

. $(dirname $0)/_init.sh

port_add p0
port_add p1
grcli address add fd00:102::1/32 iface p1
grcli address add 192.168.61.1/24 iface p0

for n in 0 1; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	move_to_netns $p $ns
done
ip -n n0 addr add 192.168.61.2/24 dev x-p0
ip -n n1 addr add fd00:102::2/32 dev x-p1

#
# Adding the same NEXT-CSID SID twice without an explicit id must update the
# nexthop created by the first call instead of creating a duplicate: the
# default block/csid lengths have to be filled in before the dedup lookup.
#
grcli nexthop add srv6-local behavior end flavor next-csid
before=$(grcli -j nexthop show type srv6-local)
grcli nexthop add srv6-local behavior end flavor next-csid \
	|| fail "re-adding an identical NEXT-CSID SID failed"
after=$(grcli -j nexthop show type srv6-local)
[ "$before" = "$after" ] || fail "the second add did not reuse the existing nexthop"
grcli nexthop del "$(grcli -j nexthop show type srv6-local | jq -r '.[0].id')"

#
# network layout:
#  (client) x-p0(netns) <--> p0 <grout> p1 <--->  x-p1(netns) (public: 192.168.60.1/24 on p0)
#       ipv4 ---------------|        srv6        |-- ipv4
#
# test case:
#   - (1) send ipv4 ping from p0
#   - (2) grout encap in srv6, send to sid fd00:202:200::
#   - (3) linux x-p1 decap it
#   - (4) reply to ping
#   - (5) linux x-p1 reencap in srv6, send to grout sid fd00:202:100::,
#   - (6) grout decap it, reply back in ipv4 to p0
#

# only linux's p1 will see srv6
ip netns exec n1 sysctl -w net.ipv6.conf.x-p1.seg6_enabled=1
ip netns exec n1 sysctl -w net.ipv6.conf.x-p1.forwarding=1

# (1) send ipv4 to grout
ip -n n0 route add default via 192.168.61.1 dev x-p0

# (2)
grcli nexthop add srv6 seglist fd00:202:200:: id 42
grcli route add 192.168.0.0/16 via id 42
grcli route add fd00:202::/32 via fd00:102::2

# (3)
ip -n n1 -6 route add fd00:202:200:: encap seg6local action End.DX4 nh4 192.168.60.1 count dev x-p1

# (4) 192.168.60.0/24 is our 'public' network
ip -n n1 addr add 192.168.60.1/24 dev x-p1

# (5)
ip -n n1 route add 192.168.61.0/24 encap seg6 mode encap segs fd00:202:100:: dev x-p1
ip -n n1 -6 route add fd00:202::/32 via fd00:102::1 dev x-p1

# (6)
grcli nexthop add srv6-local behavior end.dt4 id 666
grcli route add fd00:202:100::/48 via id 666

# test
ip netns exec n0 ping -i0.01 -c3 -n 192.168.60.1
ping -i0.01 -c3 -n 192.168.60.1 || fail "ping through an SRv6 nexthop failed"
# check that sid is reachable
ip netns exec n1 ping6 -i0.01 -c3 -n fd00:202:100::

# RFC 8986 section 6: the SID counts the packets it successfully processed.
grcli -j nexthop show id 666 | jq -e '.packets > 0' >/dev/null \
	|| fail "the End.DT4 SID did not count the packets it processed"
grcli -j nexthop show id 666 | jq -e '.bytes > 0' >/dev/null \
	|| fail "the End.DT4 SID did not count the bytes it processed"

#
# NEXT-CSID transit test
#
# A CSID container fd00:202:0300:0100:: packs two CSIDs (0300 and 0100)
# with block-bits=32, csid-bits=16. Grout matches fd00:202:0300::/48 as
# a NEXT-CSID End transit node, shifts the DA to fd00:202:0100::
# (= fd00:202:100::), and the second lookup hits the existing End.DT4
# endpoint.
#

# NEXT-CSID End transit node
grcli nexthop add srv6-local behavior end flavor next-csid id 700
grcli route add fd00:202:300::/48 via id 700

# linux sends to the CSID container instead of the single SID
ip -n n1 route replace 192.168.61.0/24 encap seg6 mode encap segs fd00:202:0300:0100:: dev x-p1

# test: ping goes through the NEXT-CSID transit node
ip netns exec n0 ping -i0.01 -c3 -n 192.168.60.1

#
# Per-nexthop encap source test
#
# Create a new SRv6 output nexthop with an explicit source address and
# verify the encapsulated packets use it as the outer IPv6 source.
#

encap_src=fd00:102::42
grcli address add $encap_src/128 iface p1
grcli nexthop add srv6 seglist fd00:202:200:: src $encap_src id 43
grcli route add 192.168.0.0/16 via id 43

ip netns exec n0 ping -c3 -n 192.168.60.1 &
ping_pid=$!

# capture a few packets on x-p1 in n1
ip netns exec n1 timeout 5 tcpdump -c1 -pnnli x-p1 ip6 src $encap_src  || {
	wait $ping_pid
	fail "encapsulated packet did not use per-nexthop encap_src $encap_src"
}

wait $ping_pid

#
# RFC 8986 section 5.1 S02: the encapsulation source must be an address
# configured on the node. Spoofed sources are refused.
#
grcli tunsrc set fd00:102::666 && fail "a non-local tunnel source was accepted"
grcli nexthop add srv6 seglist fd00:202:200:: src fd00:102::666 id 49 \
	&& fail "a non-local encap source was accepted"
grcli nexthop show id 49 && fail "the refused nexthop was created anyway"

#
# Outer Traffic Class and Flow Label test
#
# RFC 2473 section 5.1.1.1: the encapsulated packet inherits the DSCP and
# ECN marking of the inner packet. RFC 6438: it also carries a Flow Label
# so that transit routers can load balance the tunnel.
#

capture=$(mktemp)
ip netns exec n1 timeout 5 tcpdump -c1 -vnnli x-p1 'ip6 and (ip6[6] == 43 or ip6[6] == 4)' >"$capture" 2>&1 &
tcpdump_pid=$!
for _ in $(seq 50); do
	if grep -q "listening on" "$capture"; then
		break
	fi
	sleep 0.1
done

ip netns exec n0 ping -Q 0xb8 -i0.01 -c3 -n 192.168.60.1 >/dev/null 2>&1 || true

if ! wait $tcpdump_pid; then
	cat "$capture"
	rm -f "$capture"
	fail "no encapsulated packet captured on x-p1"
fi

if ! grep -q "class 0xb8" "$capture"; then
	cat "$capture"
	rm -f "$capture"
	fail "the outer Traffic Class does not inherit the inner DSCP marking"
fi

if grep -q "flowlabel 0x0," "$capture"; then
	cat "$capture"
	rm -f "$capture"
	fail "the outer IPv6 header has a zero Flow Label"
fi

if ! grep -q "hlim 64," "$capture"; then
	cat "$capture"
	rm -f "$capture"
	fail "the outer IPv6 header does not use the default Hop Limit of 64"
fi
rm -f "$capture"

#
# IPv6-in-SRv6 encapsulation test
#
# Full round-trip IPv6 ping through SRv6
#

# client side: IPv6 address and route via grout
ip -n n0 addr add fd00:61::2/64 dev x-p0
grcli address add fd00:61::1/64 iface p0
ip -n n0 -6 route add fd00:60::/64 via fd00:61::1 dev x-p0

# grout encap: IPv6 traffic toward fd00:60::/64 goes through SRv6
grcli nexthop add srv6 seglist fd00:202:600:: id 60
grcli route add fd00:60::/64 via id 60
# grout decaps the return SRv6 traffic with End.DT6
grcli nexthop add srv6-local behavior end.dt6 id 61
grcli route add fd00:202:700::/48 via id 61

# n1 decaps with End.DT6 into a VRF and replies through SRv6 back to grout
ip netns exec n1 sysctl -qw net.vrf.strict_mode=1
ip -n n1 link add vrf10 type vrf table 10
ip -n n1 link set vrf10 up
ip -n n1 addr add fd00:60::1/64 dev vrf10
ip -n n1 -6 route add fd00:202:600:: encap seg6local action End.DT6 vrftable 10 count dev x-p1
ip -n n1 -6 route add fd00:61::/64 encap seg6 mode encap segs fd00:202:700:: dev x-p1 table 10
ip -n n1 -6 route add fd00:202::/32 via fd00:102::1 dev x-p1 table 10

# test
ip netns exec n0 ping6 -i0.01 -c3 -n fd00:60::1
ping6 -i0.01 -c3 -n fd00:60::1 || fail "ping through an SRv6 nexthop failed (IPv6)"

#
# Multi-segment encapsulation test
#
# fd00:202:a00:: and fd00:202:b00:: are plain transit nodes, fd00:202:c00::
# decaps back into the public network. Linux validates the SRH of every
# packet it receives, so an SRH advertising the wrong number of entries
# breaks forwarding outright.
#

ip -n n1 -6 route add fd00:202:a00:: encap seg6local action End count dev x-p1
ip -n n1 -6 route add fd00:202:b00:: encap seg6local action End count dev x-p1
ip -n n1 -6 route add fd00:202:c00:: encap seg6local action End.DX4 \
	nh4 192.168.60.1 count dev x-p1

seglist="fd00:202:a00:: fd00:202:b00:: fd00:202:c00::"

# h.encaps carries the three segments in the SRH: last_entry=2, segments_left=2
grcli nexthop add srv6 seglist $seglist id 44
grcli route add 192.168.0.0/16 via id 44
ip netns exec n0 ping -i0.01 -c3 -n 192.168.60.1

# h.encaps.red leaves the first segment out of the SRH, it is already carried
# in the outer destination address. Only two entries remain: hdr_len=4,
# last_entry=1 and segments_left=2, which RFC 8986 4.1 allows to exceed
# last_entry by one.
grcli nexthop add srv6 seglist $seglist encap h.encaps.red id 45
grcli route add 192.168.0.0/16 via id 45

# Start the captures before the traffic. ping -i0.2 -c5 is done emitting after
# 0.8s, which tcpdump may not beat to opening its capture. The second capture
# is only there to report what was really sent when the first one fails.
ip netns exec n1 timeout 5 tcpdump -c1 -pnnli x-p1 \
	'ip6 dst fd00:202:a00:: and ip6[41] = 4 and ip6[43] = 2 and ip6[44] = 1' \
	>$tmp/srh_reduced 2>&1 &
tcpdump_pid=$!
ip netns exec n1 timeout 5 tcpdump -c1 -pnnvli x-p1 ip6 dst fd00:202:a00:: \
	>$tmp/srh_any 2>&1 &
tcpdump_any_pid=$!
for _ in $(seq 50); do
	if grep -q "listening on" $tmp/srh_reduced && grep -q "listening on" $tmp/srh_any; then
		break
	fi
	sleep 0.1
done

ip netns exec n0 ping -i0.2 -c5 -n 192.168.60.1 >/dev/null 2>&1 &
ping_pid=$!

if ! wait $tcpdump_pid; then
	wait $tcpdump_any_pid || true
	wait $ping_pid || true
	cat $tmp/srh_any
	fail "h.encaps.red did not produce a reduced SRH"
fi
wait $tcpdump_any_pid || true
wait $ping_pid || fail "h.encaps.red did not forward"

#
# uSID headend test
#
# fd00:202:0d00:0e00:: is a CSID container packing the uSIDs 0d00 and 0e00
# with block-bits=32, csid-bits=16. grout only copies segment list entries, so
# a container goes through both encap behaviors untouched. With h.encaps.red
# and a single container no SRH is left at all, which is the usual uSID
# deployment.
#

ip -n n1 -6 route add fd00:202:0d00::/48 encap seg6local action End \
	flavors next-csid lblen 32 nflen 16 dev x-p1
ip -n n1 -6 route add fd00:202:0e00:: encap seg6local action End.DX4 \
	nh4 192.168.60.1 count dev x-p1

# h.encaps still emits an SRH holding the container alone, segments_left=0
grcli nexthop add srv6 seglist fd00:202:0d00:0e00:: id 46
grcli route add 192.168.0.0/16 via id 46
ip netns exec n0 ping -i0.01 -c3 -n 192.168.60.1

# h.encaps.red has nothing left to put in an SRH, so the outer header must
# point straight at the inner packet instead of a routing header.
grcli nexthop add srv6 seglist fd00:202:0d00:0e00:: encap h.encaps.red id 47
grcli route add 192.168.0.0/16 via id 47

ip netns exec n1 timeout 5 tcpdump -c1 -pnnli x-p1 \
	'ip6 dst fd00:202:0d00:0e00:: and ip6[6] = 4' >$tmp/usid_nosrh 2>&1 &
tcpdump_pid=$!
ip netns exec n1 timeout 5 tcpdump -c1 -pnnvli x-p1 ip6 dst fd00:202:0d00:0e00:: \
	>$tmp/usid_any 2>&1 &
tcpdump_any_pid=$!
for _ in $(seq 50); do
	if grep -q "listening on" $tmp/usid_nosrh && grep -q "listening on" $tmp/usid_any; then
		break
	fi
	sleep 0.1
done

ip netns exec n0 ping -i0.2 -c5 -n 192.168.60.1 >/dev/null 2>&1 &
ping_pid=$!

if ! wait $tcpdump_pid; then
	wait $tcpdump_any_pid || true
	wait $ping_pid || true
	cat $tmp/usid_any
	fail "h.encaps.red on a single container still pushed an SRH"
fi
wait $tcpdump_any_pid || true
wait $ping_pid || fail "uSID container encapsulation did not forward"

#
# Underlay MTU test
#
# The encapsulated packet must fit in the underlay MTU. When it does not,
# grout must report the tunnel MTU to the source of the inner packet instead
# of silently dropping it: an ICMPv6 Packet Too Big for an IPv6 payload, an
# ICMPv4 Fragmentation Needed for an IPv4 one (RFC 2473 sections 7.1 and 7.2).
#

# h.encaps.red with a single segment leaves no SRH: the outer header is 40
# bytes, so the advertised tunnel MTU is the underlay MTU minus 40.
grcli nexthop add srv6 seglist fd00:202:200:: encap h.encaps.red id 48
grcli route add 192.168.0.0/16 via id 48
grcli route add fd00:60::/64 via id 48

underlay_mtu=1400
tunnel_mtu=$((underlay_mtu - 40))
grcli interface set port p1 mtu $underlay_mtu

ping_out=$tmp/mtu_v6
ip netns exec n0 ping6 -c1 -W1 -s 1400 -n fd00:60::1 >$ping_out 2>&1 \
	&& fail "an oversize IPv6 packet was not rejected"
grep -q "mtu=$tunnel_mtu" $ping_out || {
	cat $ping_out
	fail "no ICMPv6 Packet Too Big advertising the tunnel MTU"
}

ping_out=$tmp/mtu_v4
ip netns exec n0 ping -c1 -W1 -s 1400 -M do -n 192.168.60.1 >$ping_out 2>&1 \
	&& fail "an oversize IPv4 packet was not rejected"
grep -q "mtu = $tunnel_mtu" $ping_out || {
	cat $ping_out
	fail "no ICMPv4 Fragmentation Needed advertising the tunnel MTU"
}

grcli interface set port p1 mtu 1500

#
# RFC 8754 section 4.3.2: a packet whose destination is a plain local address
# (not an SRv6 SID) cannot be routed by its SRH. When segments are left, grout
# must answer with an ICMPv6 Parameter Problem, Code 0, instead of delivering
# the payload as if the routing had happened.
#

capture=$tmp/local_srh
ip netns exec n1 timeout 5 tcpdump -c1 -pnnli x-p1 \
	'icmp6 and ip6[40] = 4 and ip6[41] = 0' >"$capture" 2>&1 &
tcpdump_pid=$!
for _ in $(seq 50); do
	if grep -q "listening on" "$capture"; then
		break
	fi
	sleep 0.1
done

# Hand-build the frame: the kernel refuses to send an SRv6 packet whose outer
# destination is not an SRv6 SID.
p1_mac=$(grcli -j interface show name p1 | jq -r .mac)
ip netns exec n1 python3 - x-p1 "$p1_mac" <<'EOF'
import socket, struct, sys

dev, mac = sys.argv[1], bytes(int(b, 16) for b in sys.argv[2].split(":"))

ip6_src = socket.inet_pton(socket.AF_INET6, "fd00:102::2")
ip6_dst = socket.inet_pton(socket.AF_INET6, "fd00:102::1")
segments = [ip6_dst, socket.inet_pton(socket.AF_INET6, "fd00:202:200::")]

# SRH: next header ICMPv6, two segments (40 bytes, hdr_ext_len 4), routing
# type 4, one segment left.
srh = struct.pack("!BBBB", 58, 4, 4, 1)
srh += struct.pack("!BBH", 1, 0, 0) + b"".join(segments)
icmp = struct.pack("!BBH", 128, 0, 0) + b"\x00" * 8
payload = srh + icmp
ip6 = struct.pack("!IHBB", 6 << 28, len(payload), 43, 64) + ip6_src + ip6_dst

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((dev, 0))
s.send(mac + b"\x02\x00\x00\x00\x00\x01" + b"\x86\xdd" + ip6 + payload)
EOF

if ! wait $tcpdump_pid; then
	cat "$capture"
	fail "no ICMPv6 Parameter Problem for an SRH on a plain local address"
fi
