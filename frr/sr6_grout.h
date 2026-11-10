// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#pragma once

#ifdef HAVE_FRR_SRV6_L2EVPN

#include <stdint.h>

#include <zebra/zebra_dplane.h>

// DPLANE_OP_SR6_UPDATE_SID (dplane_sr6_program/dplane_sr6_update_sid):
// program (or reset with an all-zero SID) the encap segment of an SRv6
// L2 EVPN / VPWS tunnel port.
enum zebra_dplane_result grout_sr6_update_sid_ctx(struct zebra_dplane_ctx *ctx);

// DPLANE_OP_BRPORT_FLAGS (dplane_sr6_brport_flags): EVPN bridge-port
// profile (learning/flood/isolation) for an SRv6 tunnel port.
enum zebra_dplane_result grout_sr6_brport_flags_ctx(struct zebra_dplane_ctx *ctx);

// DPLANE_OP_BRIDGE_VLAN_ADD (dplane_sr6_bridge_vlan_add): EVI VLAN
// membership of an SRv6 tunnel port on its bridge.
enum zebra_dplane_result grout_sr6_bridge_vlan_add_ctx(struct zebra_dplane_ctx *ctx);

// Forget the encap state tracked for a removed grout interface (iface
// delete path of grout_link_change).
void grout_sr6_port_del(uint16_t iface_id);

#endif // HAVE_FRR_SRV6_L2EVPN
