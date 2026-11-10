#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# SRv6 L2 EVPN (RFC 9252) control plane between FRR+grout and a standalone
# FRR peer, using the SRv6 L2 EVPN fork of FRR (frr_version srv6-l2evpn).
#
# The peer runs the same FRR build on the kernel, which has no "sr6" netdev
# support: its control plane (SID allocation, BGP EVPN type-2/type-3 with
# the SRv6 L2 Service TLV) works but its dataplane does not forward. This
# test therefore verifies the full control plane convergence and the grout
# programming: the sr6 tunnel ports carry the remote PE SIDs, the remote
# MAC FDB entries point at the unicast sr6 port, and the local End.DX2/
# DT2U/DT2M decap SIDs are installed.
#
# The datapath itself is covered by srv6_l2vpn_test.sh.
#
#        |-------------- grout (PE1) -------------|      |---- PE2 (linux) ----|
#        |                                         |      |                     |
#        |  br-bundle: p1 + sr6-1 + bum-sr6-1      |      |  br-bundle: p1      |
#        |  br-vpws:   p2 + vpws-sr6-T1            |      |  br-vpws:   p2      |
#        |                                         |      |                     |
#        |  p0: 2001:db8:20::1/64                  | <--> |  x-p0: 2001:db8:20::2/64
#        |  locator fcbb:bbbb:1::/48               |  BGP |  locator fcbb:bbbb:2::/48

. $(dirname $0)/_init_frr.sh

PEER_LOCATOR=fcbb:bbbb:2::
LOCATOR=fcbb:bbbb:1::
PEER_MAC=02:00:00:00:00:11

# ---------------------------------------------------------------- grout side

create_interface p0
set_ip_address p0 2001:db8:20::1/64
# The EVPN type-2/type-3 next-hop is the bgp router-id: it must be
# reachable over the underlay.
set_ip_address p0 192.0.2.101/24

# Operator-owned model: the bridges and the sr6 tunnel ports are created
# before FRR is configured; zebra discovers the ports by name on the
# bridges and programs them in place.
create_interface p1
grcli interface add bridge br-bundle
grcli interface set port p1 domain br-bundle
# Local MAC advertised as EVPN type-2.
grcli fdb add 02:00:00:00:00:01 iface p1

create_interface p2
grcli interface add bridge br-vpws
grcli interface set port p2 domain br-vpws

# Unicast (End.DT2U) port: known unicast only, no BUM flooding.
# BUM (End.DT2M) port: bridge flooding toward the remote PE.
grcli interface add sr6 sr6-1 domain br-bundle
grcli interface add sr6 bum-sr6-1 domain br-bundle flood on
grcli interface add sr6 vpws-sr6-T1 domain br-vpws flood on

# Underlay reachability of the remote locator.
grcli route add $PEER_LOCATOR/48 via 2001:db8:20::2

# ------------------------------------------------------------------ PE2 side

start_frr evpn-peer 0

move_to_netns x-p0 evpn-peer
ip -n evpn-peer addr add 2001:db8:20::2/64 dev x-p0
ip -n evpn-peer addr add 192.0.2.102/24 dev x-p0
ip -n evpn-peer -6 route add $LOCATOR/48 via 2001:db8:20::1

ip -n evpn-peer link add br-bundle type bridge
ip -n evpn-peer link set br-bundle up
ip -n evpn-peer link add p1 type dummy
ip -n evpn-peer link set p1 master br-bundle
ip -n evpn-peer link set p1 up
# Local MAC advertised as EVPN type-2.
bridge -n evpn-peer fdb add $PEER_MAC dev p1 master static

ip -n evpn-peer link add br-vpws type bridge
ip -n evpn-peer link set br-vpws up
ip -n evpn-peer link add p2 type dummy
ip -n evpn-peer link set p2 master br-vpws
ip -n evpn-peer link set p2 up

vtysh -N evpn-peer <<-EOF
configure terminal
segment-routing
 srv6
  locators
   locator LOC2
    prefix $PEER_LOCATOR/48
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

# -------------------------------------------------------------- grout FRR side

vtysh <<-EOF
configure terminal
segment-routing
 srv6
  locators
   locator LOC1
    prefix $LOCATOR/48
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

# ------------------------------------------------------------------- verify

# BGP session established: the summary state column shows a transient
# state (Idle/Connect/Active/Open...) until the session comes up, then it
# shows the received prefix count.
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

# Remote MAC (type-2) installed on the unicast sr6 port.
attempts=0
while ! grcli fdb show | grep -q "$PEER_MAC.*sr6-1"; do
	[ $attempts -ge 15 ] && {
		grcli fdb show
		vtysh -c "show bgp l2vpn evpn"
		vtysh -c "show evpn vni"
		vtysh -N evpn-peer -c "show bgp l2vpn evpn"
		vtysh -N evpn-peer -c "show evpn vni"
		fail "remote MAC $PEER_MAC not installed on sr6-1"
	}
	sleep 1
	attempts=$((attempts + 1))
done

# Remote service SIDs (type-2 DT2U + type-3 DT2M + VPWS DX2) programmed as
# the sr6 ports encapsulation segments.
for port in sr6-1 bum-sr6-1 vpws-sr6-T1; do
	attempts=0
	while ! grcli interface show type sr6 | grep -q "$port.*remote_sid=${PEER_LOCATOR%:}"; do
		[ $attempts -ge 15 ] && {
			grcli interface show type sr6
			fail "$port did not learn the remote SID"
		}
		sleep 1
		attempts=$((attempts + 1))
	done
done

# Local End.DX2/DT2U decap SIDs installed through the seg6local route path
# (they are /128 routes with an srv6-local nexthop on the l2dev). The fork's
# bgpd installs the BUM SID with the End.DT2U action on the same l2dev, so
# there is no end.dt2m nexthop: both unicast and BUM SIDs decap through the
# bridge FDB path.
for behavior in end.dt2u end.dx2; do
	attempts=0
	while ! grcli nexthop show | grep -q "$behavior"; do
		[ $attempts -ge 15 ] && {
			grcli nexthop show
			fail "local SID $behavior not installed"
		}
		sleep 1
		attempts=$((attempts + 1))
	done
done

grcli interface show type sr6
grcli fdb show
grcli nexthop show
grcli route show
vtysh -c "show bgp l2vpn evpn"
