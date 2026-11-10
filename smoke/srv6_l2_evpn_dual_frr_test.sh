#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# SRv6 L2 EVPN (RFC 9252) forwarding between TWO grout+FRR PE instances.
#
# Linux cannot provide the SRv6 L2 service dataplane (no sr6 netdev support),
# so the peer PE of srv6_l2_evpn_frr_test.sh cannot forward. Here the peer
# runs a SECOND grout process inside the evpn-peer network namespace, with
# its own API socket and its own FRR (zebra with the dplane_grout plugin
# connected to that socket, bgpd). Both PEs being grout, full E-LAN
# (End.DT2U/DT2M) and VPWS (End.DX2) forwarding works in both directions.
#
# The two data planes are cabled at L2: each grout underlay port's kernel TAP
# (the DPDK net_tap device, x-p0/x-p0b) is bridged over a veth pair. The
# control planes are not affected: FRR daemons talk to the per-interface
# control plane representors (named after the grout interfaces), which are
# plain devices in their own namespaces.
#
#     |------ grout PE1 (host ns) ------|          |------ grout PE2 (evpn-peer ns) ------|
#     |                                 |          |                                     |
#     | br-bundle: p1 + sr6-1 + bum-1   |          | br-bundle: pac1 + sr6-2 + bum-2     |
#     | br-vpws:   p2 + vpws-sr6-T1     |          | br-vpws:   pac2 + vpws-sr6-T2       |
#     |                                 |          |                                     |
#     | p0: 2001:db8:20::1/64           |          | pub0: 2001:db8:20::2/64             |
#     |     192.0.2.101/24              |          |      192.0.2.102/24                 |
#     |     wire TAP x-p0               |          |      wire TAP x-p0b                 |
#     |        |                        |          |        |                            |
#     |   br-under --- vp0 <==veth==> vp1 --- br-under-peer                        |
#     |                                 |          |                                     |
#     | FRR1: AS 65001, fcbb:bbbb:1::/48|  BGP     | FRR2: AS 65002, fcbb:bbbb:2::/48    |
#     |      (locator LOC1)             | <------> |      (locator LOC2)                 |
#     |                                 |          |                                     |
#     | host-b 10.0.0.2   host-c        |          | host-a 10.0.0.1     host-d          |
#     |        (elan)     10.0.1.2      |          |        (elan)       10.0.1.1        |
#     |                   (vpws)        |          |                     (vpws)          |

. $(dirname $0)/_init_frr.sh

PEER_SOCK=$tmp/peer-grout.sock

peer_grcli() {
	GROUT_SOCK_PATH=$PEER_SOCK grcli "$@"
}

peer_create_interface() {
	local p="$1"
	shift
	local count=0

	peer_grcli interface add port "$p" "$@"
	while vtysh -N evpn-peer -c "show interface $p" 2>&1 | grep -q "% Can't find interface"; do
		if [ "$count" -ge 25 ]; then
			fail "Interface $p not found in the peer FRR after $count attempts."
		fi
		sleep 0.2
		count=$((count + 1))
	done
}

# ------------------------------------------------------------------ grout PE1

create_interface p0
set_ip_address p0 2001:db8:20::1/64
# The EVPN type-2/type-3 next-hop is the bgp router-id: it must be
# reachable over the underlay.
set_ip_address p0 192.0.2.101/24

grcli interface add bridge br-bundle
create_interface p1
grcli interface set port p1 domain br-bundle
grcli interface add bridge br-vpws
create_interface p2
grcli interface set port p2 domain br-vpws

# Operator-owned model: unicast (End.DT2U) ports carry known unicast only,
# BUM (End.DT2M) ports receive bridge floods, VPWS (End.DX2) ports flood.
grcli interface add sr6 sr6-1 domain br-bundle
grcli interface add sr6 bum-sr6-1 domain br-bundle flood on
grcli interface add sr6 vpws-sr6-T1 domain br-vpws flood on

netns_add host-b
move_to_netns x-p1 host-b
ip -n host-b addr add 10.0.0.2/24 dev x-p1
netns_add host-c
move_to_netns x-p2 host-c
ip -n host-c addr add 10.0.1.2/24 dev x-p2

# ------------------------------------------------------------------ grout PE2

# Create the peer namespace first so the second grout process can start in
# it before FRR: the peer zebra's dplane_grout plugin then connects to the
# peer grout API socket right away (start_frr waits for the connection).
netns_add evpn-peer

# Second grout process, inside the peer namespace. Test mode (no hugepages)
# and the same reduced pool sizes as the main instance. The openmetrics
# endpoint is per-network-namespace, so the default port cannot conflict
# with the main instance. The CPU affinity differs from the main instance.
peer_cpu=$(( (cpu + 2) % ($(nproc) - 1) ))
ip netns exec evpn-peer env \
	GROUT_MAX_IFACES=64 GROUT_MEMPOOL_CHUNK_SIZE=2047 GROUT_MAX_NEXTHOPS=128 \
	GROUT_MAX_ROUTES=128 GROUT_MAX_FDB_ENTRIES=128 GROUT_MAX_CONNTRACKS=32 \
	GROUT_PORT_QUEUE_SIZE=32 GROUT_CP_MEMPOOL_SIZE=32 \
	taskset -c $peer_cpu,$((peer_cpu + 1)) \
	grout -t -s $PEER_SOCK -m 0666 >$tmp/peer-grout.log 2>$tmp/peer-grout.err &
peer_grout_pid=$!
echo "kill $peer_grout_pid 2>/dev/null || true" >>$tmp/cleanup

attempts=0
while ! socat FILE:/dev/null UNIX-CONNECT:$PEER_SOCK 2>/dev/null; do
	kill -0 $peer_grout_pid || { cat $tmp/peer-grout.err; fail "peer grout died"; }
	if [ $attempts -ge 30 ]; then
		cat $tmp/peer-grout.err
		fail "peer grout took more than 30s to start"
	fi
	sleep 1
	attempts=$((attempts + 1))
done
peer_grcli log level set grout*:info
peer_grcli trace enable all

# The peer FRR, with its zebra's dplane_grout plugin connected to the peer
# grout API socket.
saved_sock=$GROUT_SOCK_PATH
export GROUT_SOCK_PATH=$PEER_SOCK
start_frr evpn-peer 1
export GROUT_SOCK_PATH=$saved_sock

peer_create_interface pub0 devargs net_tap0,iface=x-p0b
# Give the wire TAP a MAC different from the grout port MAC: the kernel
# bridge cabling the two data planes must not own the peer port MAC, or
# unicast frames toward it are delivered to the bridge itself instead of
# the wire TAP.
ip -n evpn-peer link set x-p0b address "$(stable_mac pub0)"
peer_grcli address add 2001:db8:20::2/64 iface pub0
peer_grcli address add 192.0.2.102/24 iface pub0

peer_grcli interface add bridge br-bundle
peer_create_interface pac1 devargs net_tap1,iface=x-pac1
peer_grcli interface set port pac1 domain br-bundle
peer_grcli interface add bridge br-vpws
peer_create_interface pac2 devargs net_tap2,iface=x-pac2
peer_grcli interface set port pac2 domain br-vpws

peer_grcli interface add sr6 sr6-2 domain br-bundle
peer_grcli interface add sr6 bum-sr6-2 domain br-bundle flood on
peer_grcli interface add sr6 vpws-sr6-T2 domain br-vpws flood on

netns_add host-a
ip -n evpn-peer link set x-pac1 netns host-a
ip -n host-a link set x-pac1 up
ip -n host-a addr add 10.0.0.1/24 dev x-pac1
netns_add host-d
ip -n evpn-peer link set x-pac2 netns host-d
ip -n host-d link set x-pac2 up
ip -n host-d addr add 10.0.1.1/24 dev x-pac2

# ------------------------------------------------------------------- the cable

# L2-connect the two underlay wire TAPs. Only the DPDK net_tap devices are
# bridged; the control plane representors (p0/pub0) stay plain devices in
# their own namespaces. Multicast snooping is disabled: the wire TAPs carry
# no IPv6 address so the kernel bridges see no MLD listener for the
# solicited-node groups targeted by the PEs neighbor solicitations, and
# would filter them.
ip link add br-under type bridge mcast_snooping 0
ip link set br-under up
ip link set x-p0 master br-under
ip link add vp0 type veth peer name vp1
ip link set vp0 master br-under
ip link set vp0 up
ip link set netns evpn-peer dev vp1
ip -n evpn-peer link set vp1 up
ip -n evpn-peer link add br-under type bridge mcast_snooping 0
ip -n evpn-peer link set br-under up
ip -n evpn-peer link set x-p0b master br-under
ip -n evpn-peer link set vp1 master br-under
cat >>$tmp/cleanup <<'EOF'
ip link del br-under 2>/dev/null || true
ip link del vp0 2>/dev/null || true
EOF

# Underlay reachability of the remote locators.
grcli route add fcbb:bbbb:2::/48 via 2001:db8:20::2
peer_grcli route add fcbb:bbbb:1::/48 via 2001:db8:20::1

# ------------------------------------------------------------------ FRR PE2

vtysh -N evpn-peer <<-EOF
configure terminal
segment-routing
 srv6
  locators
   locator LOC2
    prefix fcbb:bbbb:2::/48
   exit
  exit
  l2-evpn
   evi 100 locator LOC2 bridge br-bundle
    service-type vlan-bundle
    vlan 100
   exit
  exit
 exit
exit
route-map PERMIT-ALL permit 10
exit
router bgp 65002
 bgp router-id 192.0.2.102
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 neighbor 2001:db8:20::1 remote-as 65001
 neighbor 2001:db8:20::1 update-source pub0
 segment-routing srv6
  locator LOC2
 exit
 address-family l2vpn evpn
  neighbor 2001:db8:20::1 activate
  neighbor 2001:db8:20::1 next-hop-self
  neighbor 2001:db8:20::1 route-map PERMIT-ALL in
  neighbor 2001:db8:20::1 route-map PERMIT-ALL out
  advertise-srv6-evpn
  evi 100
   rd 65002:100
   route-target both 65000:100
  exit-evi
  vpws-instance T2
   vpws-id source 200 target 100
   vpws-evi 1000
   rd 65002:1000
   route-target both 65000:1000
   interface pac2 sid auto bridge br-vpws
  exit-vpws-instance
 exit-address-family
exit
EOF

# ------------------------------------------------------------------ FRR PE1

vtysh <<-EOF
configure terminal
segment-routing
 srv6
  locators
   locator LOC1
    prefix fcbb:bbbb:1::/48
   exit
  exit
  l2-evpn
   evi 100 locator LOC1 bridge br-bundle
    service-type vlan-bundle
    vlan 100
   exit
  exit
 exit
exit
route-map PERMIT-ALL permit 10
exit
router bgp 65001
 bgp router-id 192.0.2.101
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 neighbor 2001:db8:20::2 remote-as 65002
 neighbor 2001:db8:20::2 update-source p0
 segment-routing srv6
  locator LOC1
 exit
 address-family l2vpn evpn
  neighbor 2001:db8:20::2 activate
  neighbor 2001:db8:20::2 next-hop-self
  neighbor 2001:db8:20::2 route-map PERMIT-ALL in
  neighbor 2001:db8:20::2 route-map PERMIT-ALL out
  advertise-srv6-evpn
  evi 100
   rd 65001:100
   route-target both 65000:100
  exit-evi
  vpws-instance T1
   vpws-id source 100 target 200
   vpws-evi 1000
   rd 65001:1000
   route-target both 65000:1000
   interface p2 sid auto bridge br-vpws
  exit-vpws-instance
 exit-address-family
exit
EOF

# -------------------------------------------------------------------- verify

# BGP session established: the summary state column shows a transient state
# (Idle/Connect/Active/Open...) until the session comes up, then it shows
# the received prefix count.
bgp_established() {
	local summary

	summary="$1"
	echo "$summary" | grep -q 6500 \
		&& ! echo "$summary" | grep 6500 | grep -qE 'Idle|Connect|Active|Open'
}

for side in "vtysh" "vtysh -N evpn-peer"; do
	attempts=0
	while ! bgp_established "$($side -c 'show bgp l2vpn evpn summary')"; do
		if [ $attempts -ge 15 ]; then
			vtysh -c "show bgp l2vpn evpn summary"
			vtysh -N evpn-peer -c "show bgp l2vpn evpn summary"
			fail "BGP l2vpn evpn session did not converge ($side)"
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
done

# Remote service SIDs (End.DT2U, End.DT2M, End.DX2) programmed as the sr6
# ports encapsulation segments, on both PEs.
check_sr6_ports() {
	local grcli_cmd="$1"
	local peer_locator="$2"
	shift 2
	local port

	for port in "$@"; do
		local attempts=0
		while ! $grcli_cmd interface show type sr6 | grep -q "^$port .*remote_sid=$peer_locator"; do
			if [ $attempts -ge 15 ]; then
				$grcli_cmd interface show type sr6
				fail "$port did not learn the remote SID ($grcli_cmd)"
			fi
			sleep 1
			attempts=$((attempts + 1))
		done
	done
}
check_sr6_ports grcli fcbb:bbbb:2: sr6-1 bum-sr6-1 vpws-sr6-T1
check_sr6_ports peer_grcli fcbb:bbbb:1: sr6-2 bum-sr6-2 vpws-sr6-T2

# ------------------------------------------------------------- E-LAN forwarding

# ARP (broadcast, End.DT2M + flood flags) and ICMP (unicast, End.DT2U + FDB
# entries from the EVPN type-2 routes), in both directions.
ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.1
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.2

# ------------------------------------------------------------- VPWS forwarding

ip netns exec host-c ping -i0.1 -c3 -W1 10.0.1.1
ip netns exec host-d ping -i0.1 -c3 -W1 10.0.1.2

# ------------------------------------------------------------------- state dump

grcli interface show type sr6
peer_grcli interface show type sr6
grcli fdb show
peer_grcli fdb show
