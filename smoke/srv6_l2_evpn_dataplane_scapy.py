#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# SRv6 L2 service dataplane for the FRR Linux peer of the
# srv6_l2_evpn_dataplane test: the mainline Linux kernel has no "sr6"
# netdev support, so this script is the peer PE dataplane, attached to the
# peer namespace. It bridges the two attachment circuits (p1 for the E-LAN,
# p2 for the VPWS) with the IPv6 underlay (x-p0), using the service SIDs
# negotiated by the BGP EVPN control plane (given as arguments).
#
# Frames received from the remote PE (encapsulated toward one of this
# peer's service SIDs) are decapsulated and delivered to the matching
# attachment circuit. Frames received from an attachment circuit are
# encapsulated (H.Encaps.L2) toward the matching remote PE service SID:
# E-LAN BUM frames go to the remote End.DT2M SID, E-LAN unicast frames to
# the remote End.DT2U SID, VPWS frames to the remote End.DX2 SID.

import sys
import time

from scapy.all import AsyncSniffer, Ether, IPv6, send, sendp
from scapy.layers.inet6 import IPv6ExtHdrSegmentRouting

# Remote PE (grout) service SIDs: encapsulation destinations.
LOC_DT2U, LOC_DT2M, LOC_DX2 = sys.argv[1:4]
# Local (this peer) service SIDs: decapsulation matches.
RMT_DT2U, RMT_DT2M, RMT_DX2 = sys.argv[4:7]

UNDERLAY_IFACE = "x-p0"
ELAN_AC_IFACE = "p1"
VPWS_AC_IFACE = "p2"


def is_bum(pkt):
	# IEEE 802.3 multicast bit (covers broadcast).
	return int(pkt.dst[0:2], 16) & 1


def decap(pkt):
	# Encapsulated frame from the remote PE: strip the outer IPv6 + SRH
	# and deliver the inner Ethernet frame to the attachment circuit.
	if IPv6 not in pkt:
		return
	sid = pkt[IPv6].dst
	if sid not in (RMT_DT2U, RMT_DT2M, RMT_DX2):
		return
	if IPv6ExtHdrSegmentRouting in pkt:
		inner = bytes(pkt[IPv6ExtHdrSegmentRouting].payload)
	else:
		inner = bytes(pkt[IPv6].payload)
	if not inner:
		return
	ac = VPWS_AC_IFACE if sid == RMT_DX2 else ELAN_AC_IFACE
	sendp(Ether(inner), iface=ac, verbose=False)


def encap(pkt, sid):
	# Use the L3 send() so that scapy resolves the underlay route and the
	# remote PE ethernet address (a broadcast outer ethernet header would
	# be dropped as not-for-us by grout).
	srh = IPv6ExtHdrSegmentRouting(nh=143, segleft=0, addresses=[sid])
	send(IPv6(dst=sid) / srh / bytes(pkt), iface=UNDERLAY_IFACE, verbose=False)


def encap_elan(pkt):
	# E-LAN frame from the local client: BUM goes to the remote End.DT2M
	# SID (the remote bridge floods it), unicast to the remote End.DT2U
	# SID (the remote bridge looks it up in its FDB).
	encap(pkt, LOC_DT2M if is_bum(pkt) else LOC_DT2U)


def encap_vpws(pkt):
	# VPWS frame from the local client: cross-connected by the remote
	# End.DX2 SID.
	encap(pkt, LOC_DX2)


sniff_underlay = AsyncSniffer(iface=UNDERLAY_IFACE, prn=decap, store=False)
sniff_elan = AsyncSniffer(iface=ELAN_AC_IFACE, prn=encap_elan, store=False)
sniff_vpws = AsyncSniffer(iface=VPWS_AC_IFACE, prn=encap_vpws, store=False)
sniff_underlay.start()
sniff_elan.start()
sniff_vpws.start()

while True:
	time.sleep(1)
