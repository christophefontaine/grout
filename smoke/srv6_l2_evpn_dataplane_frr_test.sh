#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# SRv6 L2 EVPN (RFC 9252) forwarding between FRR+grout and a standalone FRR
# peer whose DATAPLANE is a scapy script: the mainline Linux kernel has no
# sr6 netdev support, so the peer PE's forwarding (End.DT2U/DT2M/DX2 decap
# and H.Encaps.L2 encap) is done in python, attached to the peer namespace.
# Unlike srv6_l2vpn_test.sh (statically configured SIDs, no FRR), the SIDs
# here are the ones allocated and advertised by the real BGP EVPN control
# plane, discovered from the SRv6 SID managers of both sides.
#
#        |--------- grout PE1 (host ns) --------|      |---- PE2 (evpn-peer, FRR+scapy) ----|
#        |                                       |      |                                    |
#        | br-bundle: p1 + sr6-1 + bum-sr6-1     |      | br-bundle: p1 (veth to host-a)     |
#        | br-vpws:   p2 + vpws-sr6-T1           |      | br-vpws:   p2 (veth to host-d)     |
#        |                                       |      |                                    |
#        | p0: 2001:db8:20::1/64, 192.0.2.101    | <--> | x-p0: 2001:db8:20::2/64, 192.0.2.102|
#        | locator fcbb:bbbb:1::/48 (LOC1)       | BGP  | locator fcbb:bbbb:2::/48 (LOC2)    |
#        |                                       |      |                                    |
#        | host-b 10.0.0.2   host-c 10.0.1.2     |      | host-a 10.0.0.1     host-d 10.0.1.1|
#        |       (elan)        (vpws)            |      |       (elan)        (vpws)         |

. $(dirname $0)/_init_frr.sh

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

# Underlay reachability of the peer locator.
grcli route add fcbb:bbbb:2::/48 via 2001:db8:20::2

# ------------------------------------------------------------------ FRR PE2

start_frr evpn-peer 0

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 2001:db8:20::2/64 dev x-p0
ip -n evpn-peer addr add 192.0.2.102/24 dev x-p0
ip -n evpn-peer -6 route add fcbb:bbbb:1::/48 via 2001:db8:20::1

# The E-LAN attachment circuit: a veth pair, the peer end enslaved to the
# kernel bridge (so the peer FRR learns the client MAC and advertises it
# as EVPN type-2), the other end in the client namespace.
ip -n evpn-peer link add br-bundle type bridge
ip -n evpn-peer link set br-bundle up
ip -n evpn-peer link add p1 type veth peer name x-p1b
ip -n evpn-peer link set p1 master br-bundle
ip -n evpn-peer link set p1 up
netns_add host-a
ip -n evpn-peer link set x-p1b netns host-a
ip -n host-a link set x-p1b up
ip -n host-a addr add 10.0.0.1/24 dev x-p1b

# The VPWS attachment circuit.
ip -n evpn-peer link add br-vpws type bridge
ip -n evpn-peer link set br-vpws up
ip -n evpn-peer link add p2 type veth peer name x-p2b
ip -n evpn-peer link set p2 master br-vpws
ip -n evpn-peer link set p2 up
netns_add host-d
ip -n evpn-peer link set x-p2b netns host-d
ip -n host-d link set x-p2b up
ip -n host-d addr add 10.0.1.1/24 dev x-p2b

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
 neighbor 2001:db8:20::1 update-source x-p0
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
   interface p2 sid auto bridge br-vpws
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
attempts=0
while true; do
	summary="$(vtysh -c 'show bgp l2vpn evpn summary')"
	if echo "$summary" | grep -q 65002 \
		&& ! echo "$summary" | grep 65002 | grep -qE 'Idle|Connect|Active|Open'; then
		break
	fi
	if [ $attempts -ge 15 ]; then
		echo "$summary"
		vtysh -N evpn-peer -c "show bgp l2vpn evpn summary"
		fail "BGP l2vpn evpn session did not converge"
	fi
	sleep 1
	attempts=$((attempts + 1))
done

# Remote service SIDs (End.DT2U, End.DT2M, End.DX2) programmed as the sr6
# ports encapsulation segments (the peer advertises them with its EVPN
# routes).
for port in sr6-1 bum-sr6-1 vpws-sr6-T1; do
	attempts=0
	while ! grcli interface show type sr6 | grep -q "^$port .*remote_sid=fcbb:bbbb:2:"; do
		if [ $attempts -ge 15 ]; then
			grcli interface show type sr6
			fail "$port did not learn the remote SID"
		fi
		sleep 1
		attempts=$((attempts + 1))
	done
done

# --------------------------------------------------- the peer's scapy dataplane

# Service SIDs allocated by the SRv6 SID managers of both PEs: the remote
# (grout) ones are the encapsulation destinations, the local (peer) ones
# the decapsulation matches.
srv6_sid() { # $1: behavior, $2: peer (empty = grout PE)
	vtysh ${2:+-N $2} -c 'show segment-routing srv6 sid json' |
		jq -r --arg b "$1" 'to_entries[] | select(.value.behavior == $b) | .key' |
		head -1
}

LOC_DT2U=$(srv6_sid End.DT2U)
LOC_DT2M=$(srv6_sid End.DT2M)
LOC_DX2=$(srv6_sid End.DX2)
RMT_DT2U=$(srv6_sid End.DT2U evpn-peer)
RMT_DT2M=$(srv6_sid End.DT2M evpn-peer)
RMT_DX2=$(srv6_sid End.DX2 evpn-peer)

for sid in "$LOC_DT2U" "$LOC_DT2M" "$LOC_DX2" "$RMT_DT2U" "$RMT_DT2M" "$RMT_DX2"; do
	[ -n "$sid" ] || fail "could not discover one of the service SIDs"
done

ip netns exec evpn-peer python3 "$(dirname $0)/srv6_l2_evpn_dataplane_scapy.py" \
	"$LOC_DT2U" "$LOC_DT2M" "$LOC_DX2" "$RMT_DT2U" "$RMT_DT2M" "$RMT_DX2" &
SCAPY_PID=$!
sleep 3
kill -0 $SCAPY_PID 2>/dev/null || fail "scapy peer dataplane failed to start"

# ------------------------------------------------------------- E-LAN forwarding

# ARP (broadcast, End.DT2M + flood flags) and ICMP (unicast, End.DT2U + FDB
# entries from the EVPN type-2 routes), in both directions. The first ping
# also seeds the MAC learning (and the type-2 advertisement of host-a's
# MAC) on the peer side.
ip netns exec host-b ping -i0.1 -c3 -W1 10.0.0.1
ip netns exec host-a ping -i0.1 -c3 -W1 10.0.0.2

# ------------------------------------------------------------- VPWS forwarding

ip netns exec host-c ping -i0.1 -c3 -W1 10.0.1.1
ip netns exec host-d ping -i0.1 -c3 -W1 10.0.1.2

# ------------------------------------------------------------------- state dump

kill $SCAPY_PID 2>/dev/null
wait $SCAPY_PID 2>/dev/null || :

grcli interface show type sr6
grcli fdb show
grcli nexthop show | grep -E "end\.(dt2|dx)"
vtysh -c "show bgp l2vpn evpn" | grep -cE "^\s*\*"
