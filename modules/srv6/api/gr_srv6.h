// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#define GR_SRV6_MODULE 0xfeef

// NB: SRv6 nexthops are managed using GR_NH_* messages from gr_infra.h

// sr routes //////////////////////////////////////////////////////

#define GR_SRV6_ROUTE_SEGLIST_COUNT_MAX 60

// SRv6 Route Headend Behaviors Signaling (RFC 8986 Section 8.4).
typedef enum : uint8_t {
	SR_H_ENCAPS,
	SR_H_ENCAPS_RED,
} gr_srv6_encap_behavior_t;

// SRv6 output nexthop information for packet encapsulation.
// Used with GR_NH_T_SR6_OUTPUT nexthops via GR_NH_ADD from gr_infra.h.
struct gr_nexthop_info_srv6 {
	gr_srv6_encap_behavior_t encap_behavior;
	struct rte_ipv6_addr encap_src;
	uint8_t n_seglist;
	struct rte_ipv6_addr seglist[];
};

enum gr_srv6_requests : uint32_t {
	GR_SRV6_TUNSRC_SET = GR_MSG_TYPE(GR_SRV6_MODULE, 0x0001),
	GR_SRV6_TUNSRC_CLEAR,
	GR_SRV6_TUNSRC_SHOW,
};

// sr tun src //////////////////////////////////////////////////////

// Set the global SRv6 tunnel source address.
struct gr_srv6_tunsrc_set_req {
	struct rte_ipv6_addr addr;
};

GR_REQ(GR_SRV6_TUNSRC_SET, struct gr_srv6_tunsrc_set_req, struct gr_empty);

// Clear the global SRv6 tunnel source address.
GR_REQ(GR_SRV6_TUNSRC_CLEAR, struct gr_empty, struct gr_empty);

// Show the current SRv6 tunnel source address.
struct gr_srv6_tunsrc_show_resp {
	struct rte_ipv6_addr addr;
};

GR_REQ(GR_SRV6_TUNSRC_SHOW, struct gr_empty, struct gr_srv6_tunsrc_show_resp);

// localsid (tunnel transit and exit) /////////////////////////////////

// SRv6 Local SID behaviors (IANA assigned values).
// See: https://www.iana.org/assignments/segment-routing/segment-routing.xhtml
// Flavors (PSP/USD) are defined as separate flags.
typedef enum : uint16_t {
	SR_BEHAVIOR_END = 0x0001, // Endpoint function.
	SR_BEHAVIOR_END_X = 0x0005, // Endpoint with L3 cross-connect.
	SR_BEHAVIOR_END_T = 0x0009, // Endpoint function with specific table.
	SR_BEHAVIOR_END_DT6 = 0x0012, // Decaps and IPv6 table lookup.
	SR_BEHAVIOR_END_DT4 = 0x0013, // Decaps and IPv4 table lookup.
	SR_BEHAVIOR_END_DT46 = 0x0014, // Decaps and IPv4/IPv6 table lookup.
	SR_BEHAVIOR_END_DX2 = 0x0015, // Decaps and L2 cross-connect (RFC 9252).
	SR_BEHAVIOR_END_DT2U = 0x0017, // Decaps and L2 unicast lookup (RFC 9252).
	SR_BEHAVIOR_END_DT2M = 0x0018, // Decaps and L2 BUM flooding (RFC 9252).
} gr_srv6_behavior_t;

// Convert SRv6 behavior enum to string representation.
static inline const char *gr_srv6_behavior_name(gr_srv6_behavior_t b) {
	switch (b) {
	case SR_BEHAVIOR_END:
		return "end";
	case SR_BEHAVIOR_END_X:
		return "end.x";
	case SR_BEHAVIOR_END_T:
		return "end.t";
	case SR_BEHAVIOR_END_DT6:
		return "end.dt6";
	case SR_BEHAVIOR_END_DT4:
		return "end.dt4";
	case SR_BEHAVIOR_END_DT46:
		return "end.dt46";
	case SR_BEHAVIOR_END_DX2:
		return "end.dx2";
	case SR_BEHAVIOR_END_DT2U:
		return "end.dt2u";
	case SR_BEHAVIOR_END_DT2M:
		return "end.dt2m";
	}
	return "?";
}

// SRv6 flavor flags for Local SID behaviors.
typedef enum : uint8_t {
	GR_SR_FL_FLAVOR_PSP = GR_BIT8(0), // Penultimate Segment Popping.
	GR_SR_FL_FLAVOR_USD = GR_BIT8(1), // Ultimate Segment Decapsulation.
	GR_SR_FL_FLAVOR_NEXT_CSID = GR_BIT8(2), // Compressed SID (RFC 9800).
} gr_srv6_flags_t;

// SRv6 local nexthop information for Local SID processing.
// Used with GR_NH_T_SR6_LOCAL nexthops via GR_NH_ADD from gr_infra.h.
struct gr_nexthop_info_srv6_local {
	uint16_t out_vrf_id;
	gr_srv6_behavior_t behavior;
	gr_srv6_flags_t flags;
	uint8_t block_bits; // Locator-block length in bits (default 32).
	uint8_t csid_bits; // Compressed SID length in bits (default 16).
	struct rte_ipv6_addr endx_addr; // END_X: L3 nexthop address (on base iface).
};

// SRv6 L2 service port (RFC 9252) /////////////////////////////////////////////

// SRv6 port configuration flags.
typedef enum : uint16_t {
	// BUM role: the port is eligible to bridge flooding. The unicast
	// role (flag cleared) only receives known-unicast traffic from FDB
	// entries, like the "unicast_flood off" bridge-port profile on Linux.
	GR_SR6_F_FLOOD = GR_BIT16(0),
#define GR_SR6_F_VALID (GR_SR6_F_FLOOD)
} gr_sr6_flags_t;

// Convert SRv6 port flag enum to string representation.
static inline const char *gr_sr6_flag_name(gr_sr6_flags_t f) {
	switch (f) {
	case GR_SR6_F_FLOOD:
		return "flood";
	}
	return "?";
}

// SRv6 port reconfiguration attribute flags.
#define GR_SR6_SET_ENCAP_VRF GR_BIT64(32)
#define GR_SR6_SET_VLAN GR_BIT64(33)
#define GR_SR6_SET_FLAGS GR_BIT64(34)
#define GR_SR6_SET_SID GR_BIT64(35)
#define GR_SR6_SET_ENCAP GR_BIT64(36)
#define GR_SR6_SET_MAC GR_BIT64(37)

// Info structure for GR_IFACE_TYPE_SR6 interfaces.
//
// An SRv6 L2 service port is the grout counterpart of the Linux "sr6"
// netdev: a bridge member standing for an SRv6 L2 service (End.DX2,
// End.DT2U or End.DT2M). Frames the bridge forwards to it (known unicast
// from FDB entries, or BUM when the flood flag is set) are encapsulated
// (H.Encaps.L2 / H.Encaps.L2.Red) toward the remote SID. Frames
// decapsulated at the local End.DT2U/End.DT2M SIDs are injected into the
// bridge through the port referenced by the SID nexthop.
struct gr_iface_info_sr6 {
	// L3 domain for the encapsulated packets (underlay).
	uint16_t encap_vrf_id;
	// FDB vlan for decapsulated frames (0 = untagged / vlan-bundle).
	uint16_t vlan_id;
	gr_sr6_flags_t flags;
	// H.Encaps.L2 (SR_H_ENCAPS) or H.Encaps.L2.Red (SR_H_ENCAPS_RED).
	gr_srv6_encap_behavior_t encap;
	// Encapsulation destination, :: = disabled.
	struct rte_ipv6_addr remote_sid;
	struct rte_ether_addr mac; // Default to random address.
};

// The datapath iface embeds the public info struct as the first field of
// its per-type info area. This lets other modules read the SRv6 port
// flood eligibility without pulling the srv6 control headers.
static inline gr_sr6_flags_t gr_sr6_iface_flags(const void *iface_info) {
	return ((const struct gr_iface_info_sr6 *)iface_info)->flags;
};
