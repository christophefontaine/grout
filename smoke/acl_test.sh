#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine, Red Hat

# Exhaustive ACL datapath test using the grout CLI only, without FRR.
# Exercises the classification engine (rte_acl) with various match
# criteria: source/destination prefixes, protocols, ports, DSCP, TCP
# flags, packet length, multiple entries, IPv6, and filter lifecycle.
#
# Every criterion is checked both ways: matching packets increment the
# filter hit counter, non matching ones leave it unchanged.
#
# Traffic is generated from a netns peer through p0 (ingress). ICMP
# packets are sent with ping; TCP/UDP packets are crafted with scapy.

. $(dirname $0)/_init.sh

peer_ip=172.16.0.2
local_ip=172.16.0.1
peer6=2001:db8::2
local6=2001:db8::1

pkts_matched() {
	grcli -j acl filter show | jq -r '.[0].pkts // 0'
}

# Send a TCP packet from the netns peer through p0.
# Usage: send_tcp [sport] [dport] [flags] [tos] [payload_len]
send_tcp() {
	local sport=${1:-12345} dport=${2:-80} flags=${3:-S} tos=${4:-0} plen=${5:-0}
	sudo ip netns exec n0 python3 -c "
from scapy.all import IP, TCP, Raw, send
ip = IP(src='${peer_ip}', dst='${local_ip}', tos=${tos})
tcp = TCP(sport=${sport}, dport=${dport}, flags='${flags}')
payload = b'X' * ${plen} if ${plen} else b''
send(ip/tcp/payload, verbose=0)
" 2>/dev/null
}

# Send a UDP packet from the netns peer through p0.
# Usage: send_udp [sport] [dport]
send_udp() {
	local sport=${1:-12345} dport=${2:-80}
	sudo ip netns exec n0 python3 -c "
from scapy.all import IP, UDP, send
ip = IP(src='${peer_ip}', dst='${local_ip}')
udp = UDP(sport=${sport}, dport=${dport})
send(ip/udp, verbose=0)
" 2>/dev/null
}

# Send an IPv6 TCP packet from the netns peer through p0.
# Usage: send_tcp6 [src] [sport] [dport] [dst]
# A multicast destination avoids the NDP resolution: the neighbor
# solicitations carry the interface global address as source and would
# match the source based filters.
send_tcp6() {
	local src=${1:-$peer6} sport=${2:-12345} dport=${3:-80} dst=${4:-$local6}
	sudo ip netns exec n0 python3 -c "
from scapy.all import IPv6, TCP, send
ip6 = IPv6(src='${src}', dst='${dst}')
tcp = TCP(sport=${sport}, dport=${dport}, flags='S')
send(ip6/tcp, iface='x-p0', verbose=0)
" 2>/dev/null
}

# Create the port and addresses (inline: create_interface is FRR-only)
grcli interface add port p0 devargs net_tap0,iface=x-p0
ip link set x-p0 address $(stable_mac p0)
grcli address add ${local_ip}/24 iface p0
grcli address add ${local6}/64 iface p0

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add $peer_ip/24 dev x-p0
ip -n n0 addr add ${peer6}/64 dev x-p0
ip -n n0 route add default via $local_ip

ping_peer() {
	ip netns exec n0 ping -c1 -W1 $local_ip 2>/dev/null
}

echo "=== 1. Baseline: no ACL ==="
ping_peer || fail "baseline ping failed"
echo "ok"

echo "=== 2. Source IP match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
ping_peer && fail "ping should be dropped by src match"
[ "$(pkts_matched)" -ge 1 ] || fail "filter counter did not increment"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
ping_peer || fail "ping should pass after cleanup"
echo "ok"

echo "=== 3. Destination IP match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 dst ${local_ip}/32
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
ping_peer && fail "ping should be dropped by dst match"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 4. Protocol match: ICMP only ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32 proto 1
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
ping_peer && fail "ICMP should be dropped by proto match"
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "filter counter did not increment"
# TCP and UDP must not match a proto=1 (ICMP) rule.
send_tcp 12345 80 S
send_udp 12345 80
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "TCP/UDP should not match proto=1"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 5. Protocol match: TCP only ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32 proto 6
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
ping_peer || fail "ICMP should pass (proto=6 is TCP only)"
send_tcp 12345 80 S
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "TCP packet should match proto=6 filter"
# UDP (17) must not match a proto=6 rule.
send_udp 12345 80
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "UDP should not match proto=6"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 6. Source port match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32 sport 12345 proto 6
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
send_tcp 12345 80 S
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "TCP sport=12345 should match filter"
send_tcp 12346 80 S
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "TCP sport=12346 should not match"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 7. Destination port match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32 dport 80 proto 6
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
send_tcp 12345 80 S
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "TCP dport=80 should match filter"
send_tcp 12345 81 S
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "TCP dport=81 should not match"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 8. Port range match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32 dport 1000:2000 proto 6
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
send_tcp 12345 1500 S
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "TCP dport=1500 should match range filter"
send_tcp 12345 2001 S
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "TCP dport=2001 should not match range"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 9. DSCP match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32
grcli acl filter add 2 set 1 family ipv4 action drop iface p0 dscp 46
# DSCP 46 (EF) is carried in the ToS byte as 46 << 2 = 184.
send_tcp 12345 80 S 184
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "DSCP=46 packet should match filter"
send_tcp 12345 80 S 0
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "DSCP=0 packet should not match"
grcli acl filter del 2
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 10. TCP flags match (SYN only) ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32 proto 6
# A bare value matches the flags byte exactly: 2 = SYN, nothing else.
grcli acl filter add 3 set 1 family ipv4 action drop iface p0 tcp-flags 2
send_tcp 12345 80 S
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "TCP SYN should match flags filter"
send_tcp 12345 80 A
send_tcp 12345 80 SA
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "ACK/SYN+ACK should not match SYN filter"
grcli acl filter del 3
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 11. Packet length match ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32
grcli acl filter add 4 set 1 family ipv4 action drop iface p0 pkt-len 100:200
# The IP total length is 20 (IP) + 20 (TCP) + payload.
send_tcp 12345 80 S 0 80
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "pkt-len 100-200 should match 100-byte packet"
send_tcp 12345 80 S 0 300
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "340-byte packet should not match 100-200"
grcli acl filter del 4
# A bare length is an exact match.
grcli acl filter add 5 set 1 family ipv4 action drop iface p0 pkt-len 120
send_tcp 12345 80 S 0 80
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "pkt-len 120 should match 120-byte packet"
send_tcp 12345 80 S 0 81
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "121-byte packet should not match pkt-len 120"
grcli acl filter del 5
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 12. Multiple entries in one set ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src 10.99.99.1/32
grcli acl entry add 1 2 src ${peer_ip}/32 dport 80 proto 6
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
send_tcp 12345 80 S
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "second entry should match"
send_tcp 12345 81 S
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "dport=81 should not match the second entry"
grcli acl filter del 1
grcli acl entry del 1 2
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 13. Multiple filters (both drop) ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32
grcli acl filter add 10 set 1 family ipv4 action drop iface p0
grcli acl filter add 20 set 1 family ipv4 action drop iface p0
ping_peer && fail "ping should be dropped by either filter"
grcli acl filter del 10
grcli acl filter del 20
grcli acl entry del 1 1
grcli acl set del 1
ping_peer || fail "ping should pass after both filters removed"
echo "ok"

echo "=== 14. Non-matching entry (different source) ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src 10.50.50.1/32
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
ping_peer || fail "ping should pass (entry matches different src)"
[ "$(pkts_matched)" -eq 0 ] || fail "filter should not match"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 15. Filter without interface (no-op) ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32
grcli acl filter add 1 set 1 family ipv4 action drop
ping_peer || fail "ping should pass (filter has no interface)"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 16. Entry update (change match criteria) ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src 10.50.50.1/32
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
ping_peer || fail "ping should pass (non-matching entry)"
# Update the entry to match the peer
grcli acl entry add 1 1 src ${peer_ip}/32
ping_peer && fail "ping should be dropped after entry update"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1
echo "ok"

echo "=== 17. Set deletion blocked when referenced ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 1 src ${peer_ip}/32
grcli acl filter add 1 set 1 family ipv4 action drop iface p0
grcli acl set del 1 2>/dev/null && fail "set deletion should fail with EBUSY"
grcli acl filter del 1
grcli acl entry del 1 1
grcli acl set del 1 || fail "set deletion should succeed after cleanup"
echo "ok"

echo "=== 18. Entry id auto allocation ==="
grcli acl set add 1 family ipv4 type net
grcli acl entry add 1 src 10.0.0.1/32
[ "$(grcli -j acl entry show set 1 | jq length)" -eq 1 ] || fail "auto allocated entry not listed"
grcli acl entry del 1 "$(grcli -j acl entry show set 1 | jq -r '.[0].entry')"
grcli acl set del 1
echo "ok"

echo "=== 19. IPv6 source match ==="
grcli acl set add 6 family ipv6 type net
grcli acl entry add 6 1 src ${peer6}/128
grcli acl filter add 6 set 6 family ipv6 action drop iface p0
send_tcp6 ${peer6} 12345 80
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "IPv6 TCP should match src filter"
# Multicast destination: no NDP solicitation, and the packet still goes
# through the ingress ACL (it runs before the multicast handling).
send_tcp6 fe80::1 12345 80 ff02::1
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "different IPv6 src should not match"
grcli acl filter del 6
grcli acl entry del 6 1
grcli acl set del 6
echo "ok"

echo "=== 20. IPv6 source port match ==="
grcli acl set add 6 family ipv6 type net
grcli acl entry add 6 1 src ${peer6}/128 sport 12345 proto 6
grcli acl filter add 6 set 6 family ipv6 action drop iface p0
send_tcp6 ${peer6} 12345 80
sleep 0.2
n=$(pkts_matched)
[ "$n" -ge 1 ] || fail "IPv6 TCP sport=12345 should match filter"
send_tcp6 ${peer6} 12346 80
sleep 0.2
[ "$(pkts_matched)" -eq "$n" ] || fail "IPv6 TCP sport=12346 should not match"
grcli acl filter del 6
grcli acl entry del 6 1
grcli acl set del 6
echo "ok"

echo "=== 21. Final: all traffic passes after cleanup ==="
ping_peer || fail "ping should pass at the end"
echo "ok"

echo "=== ALL ACL TESTS PASSED ==="

true
