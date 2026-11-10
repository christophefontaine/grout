#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# Remote PE for the SRv6 L2 service smoke test: bridges the veth0 client
# network with the grout SRv6 underlay (x-p1).
#
# Frames received from grout (encapsulated toward one of this script's
# service SIDs) are decapsulated and delivered to the client on veth0.
# Frames received from the client on veth0 are encapsulated (H.Encaps.L2)
# toward the matching grout service SID:
#   - vpws mode: every frame goes to the grout End.DX2 SID,
#   - elan mode: BUM frames go to the grout End.DT2M SID, unicast frames
#     to the grout End.DT2U SID.

import sys
import time

from scapy.all import AsyncSniffer, Ether, IPv6, send, sendp
from scapy.layers.inet6 import IPv6ExtHdrSegmentRouting

# grout (local) service SIDs.
LOC_DX2 = "5f00::"
LOC_DT2U = "5f00:2::"
LOC_DT2M = "5f00:3::"
# This script's (remote) service SIDs.
RMT_DX2 = "5f00:1::"
RMT_DT2U = "5f00:12::"
RMT_DT2M = "5f00:13::"

mode = sys.argv[1] if len(sys.argv) > 1 else "elan"


def is_bum(pkt):
    # IEEE 802.3 multicast bit (covers broadcast).
    return int(pkt.dst[0:2], 16) & 1


def decap(pkt):
    # Encapsulated frame from grout: strip the outer IPv6 + SRH and
    # deliver the inner Ethernet frame to the remote client.
    if IPv6 not in pkt:
        return
    if pkt[IPv6].dst not in (RMT_DX2, RMT_DT2U, RMT_DT2M):
        return
    if IPv6ExtHdrSegmentRouting in pkt:
        inner = bytes(pkt[IPv6ExtHdrSegmentRouting].payload)
    else:
        inner = bytes(pkt[IPv6].payload)
    if inner:
        sendp(Ether(inner), iface="veth0", verbose=False)


def encap(pkt):
    # Ethernet frame from the remote client: encapsulate toward the
    # grout service SID. Use the L3 send() so that scapy resolves the
    # underlay route and the grout ethernet address (a broadcast outer
    # ethernet header would be dropped as not-for-us by grout).
    if mode == "vpws":
        sid = LOC_DX2
    elif is_bum(pkt):
        sid = LOC_DT2M
    else:
        sid = LOC_DT2U
    srh = IPv6ExtHdrSegmentRouting(nh=143, segleft=0, addresses=[sid])
    send(IPv6(dst=sid) / srh / bytes(pkt), iface="x-p1", verbose=False)


sniff_underlay = AsyncSniffer(iface="x-p1", prn=decap, store=False)
sniff_client = AsyncSniffer(iface="veth0", prn=encap, store=False)
sniff_underlay.start()
sniff_client.start()

while True:
    time.sleep(1)
