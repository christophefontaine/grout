#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

. $(dirname $0)/_init.sh

# SRv6 L2 service datapath (RFC 9252): exercise the sr6 bridge ports, the
# End.DX2 / End.DT2U / End.DT2M local SID behaviors and the H.Encaps.L2
# encapsulation, in both the full and reduced modes. A scapy script acts
# as the remote PE on the other side of the IPv6 underlay.
#
#                   |------------ grout ------------|     |--- remote PE ---|
# n0 (client) <----> p0 [br0/br1] {pw0|sr6-1,bum-sr6-1} <----> p1 <----> n1/n2

# 5f00::/16 is reserved for SRv6 (RFC 8986).
LOC_DX2=5f00::
LOC_DT2U=5f00:2::
LOC_DT2M=5f00:3::
RMT_DX2=5f00:1::
RMT_DT2U=5f00:12::
RMT_DT2M=5f00:13::

port_add p0 # local attachment circuit
port_add p1 mtu 1600 # underlay toward the remote PE

netns_add n0
move_to_netns x-p0 n0
netns_add n1
move_to_netns x-p1 n1

grcli address add 2001:db8:1::1/64 iface p1
ip -n n1 addr add 2001:db8:1::2/64 dev x-p1
ip -n n1 -6 route add $RMT_DX2/128 via 2001:db8:1::1
ip -n n1 -6 route add $LOC_DX2/128 via 2001:db8:1::1
ip -n n1 -6 route add $LOC_DT2U/128 via 2001:db8:1::1
ip -n n1 -6 route add $LOC_DT2M/128 via 2001:db8:1::1

# The remote client behind the scapy PE.
netns_add n2
ip link add veth0 type veth peer name veth1
ip link set netns n1 dev veth0
ip -n n1 link set veth0 up
ip link set netns n2 dev veth1
ip -n n2 link set veth1 up

# Underlay reachability of the remote service SIDs.
grcli route add $RMT_DX2/128 via 2001:db8:1::2
grcli route add $RMT_DT2U/128 via 2001:db8:1::2
grcli route add $RMT_DT2M/128 via 2001:db8:1::2

start_scapy() {
	ip netns exec n1 python3 "$(dirname $0)/srv6_l2vpn_scapy.py" "$1" &
	SCAPY_PID=$!
	sleep 3
	if ! kill -0 $SCAPY_PID 2>/dev/null; then
		fail "scapy remote PE failed to start"
	fi
}

stop_scapy() {
	kill $SCAPY_PID 2>/dev/null
	wait $SCAPY_PID 2>/dev/null || :
}

# ---------------------------------------------------------------- VPWS (End.DX2)

ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n2 addr add 172.16.0.1/24 dev veth1

grcli interface add bridge br0
grcli interface add sr6 pw0 domain br0 flood on remote_sid $RMT_DX2
grcli interface set port p0 domain br0

# Local End.DX2 SID: decapsulate and cross-connect to the attachment circuit.
grcli nexthop add srv6-local behavior end.dx2 iface p0 id 2
grcli route add $LOC_DX2/128 via id 2

start_scapy vpws

# AC -> sr6 port (bridge flood) -> H.Encaps.L2 toward the remote End.DX2
# SID -> scapy decap -> veth1; reply the other way around (End.DX2 decap
# -> direct output on p0).
ip netns exec n0 ping -i0.1 -c3 172.16.0.1

stop_scapy

grcli interface set port p0 vrf main
grcli nexthop del 2
grcli route del $LOC_DX2/128
grcli interface del pw0
grcli interface del br0

# ------------------------------------------------------------- E-LAN (End.DT2U/DT2M)

ip -n n0 addr add 172.16.1.2/24 dev x-p0
ip -n n2 addr add 172.16.1.1/24 dev veth1
REMOTE_MAC=$(ip -n n2 link show veth1 | sed -nE 's#.*link/ether ([0-9a-f:]+).*#\1#p')

grcli interface add bridge br1
grcli interface add sr6 sr6-1 domain br1 remote_sid $RMT_DT2U
grcli interface add sr6 bum-sr6-1 domain br1 flood on remote_sid $RMT_DT2M
grcli interface set port p0 domain br1

# Known remote unicast MACs are served by the unicast-role port: the
# remote MAC FDB entries an EVPN control plane would install.
grcli fdb add $REMOTE_MAC iface sr6-1

# Local End.DT2U (unicast FDB lookup) and End.DT2M (BUM flooding) SIDs.
grcli nexthop add srv6-local behavior end.dt2u iface sr6-1 id 3
grcli route add $LOC_DT2U/128 via id 3
grcli nexthop add srv6-local behavior end.dt2m iface bum-sr6-1 id 4
grcli route add $LOC_DT2M/128 via id 4

start_scapy elan

# Unicast (ARP + ICMP) exercises End.DT2U decap and the FDB entries;
# broadcast ARP exercises End.DT2M decap and the flood flags.
ip netns exec n0 ping -i0.1 -c3 172.16.1.1
# The reverse direction: the remote client's broadcast ARP goes through
# the remote End.DT2M SID.
ip netns exec n2 ping -i0.1 -c3 172.16.1.2

# RFC 9252 End.DT2M: a known-unicast frame received on the BUM SID is
# still flooded (the FDB is not consulted), unlike End.DT2U which only
# forwards it to the FDB port. Inject one toward the local End.DT2M SID
# with the remote client MAC as destination (a known unicast in the FDB)
# and check it is flooded to the local client.
ip netns exec n0 timeout 5 tcpdump -i x-p0 -c1 -nn host 172.16.31.31 >$tmp/dt2m_flood.log 2>&1 &
TCPD_PID=$!
sleep 1
ip netns exec n1 python3 - "$LOC_DT2M" "$REMOTE_MAC" <<'EOF'
import sys

from scapy.all import Ether, ICMP, IP, IPv6, send
from scapy.layers.inet6 import IPv6ExtHdrSegmentRouting

sid, remote_mac = sys.argv[1:3]
srh = IPv6ExtHdrSegmentRouting(nh=143, segleft=0, addresses=[sid])
frame = Ether(src="02:00:00:00:00:99", dst=remote_mac)
frame /= IP(src="172.16.31.31", dst="172.16.1.2") / ICMP()
send(IPv6(dst=sid) / srh / bytes(frame), iface="x-p1", verbose=False)
EOF
if ! wait $TCPD_PID; then
	cat $tmp/dt2m_flood.log
	fail "End.DT2M did not flood the known-unicast frame"
fi

stop_scapy

# Reduced encapsulation mode: single SID in the IPv6 destination address,
# no SRH.
grcli interface set sr6 sr6-1 encap reduced
grcli interface set sr6 bum-sr6-1 encap reduced

start_scapy elan

ip netns exec n0 ping -i0.1 -c3 172.16.1.1

stop_scapy
