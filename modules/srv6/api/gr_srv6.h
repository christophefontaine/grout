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
	}
	return "?";
}

// SRv6 flavor flags for Local SID behaviors.
typedef enum : uint8_t {
	GR_SR_FL_FLAVOR_PSP = GR_BIT8(0), // Penultimate Segment Popping.
	GR_SR_FL_FLAVOR_USD = GR_BIT8(1), // Ultimate Segment Decapsulation.
	GR_SR_FL_FLAVOR_NEXT_CSID = GR_BIT8(2), // Compressed SID (RFC 9800).
	GR_SR_FL_FLAVOR_USP = GR_BIT8(3), // Ultimate Segment Pop of the SRH.
} gr_srv6_flags_t;

// Upper-layer headers that a local SID terminates, as a bitmap: one bit per
// IPv6 Next Header value (RFC 8200 section 4.7), so that any protocol can be
// allowed without growing the structure.
#define GR_SRV6_ULP_BITMAP_LEN 32

// Default allow-list: ICMPv6 only. RFC 8986 section 4.1.1 recommends allowing
// only the headers that do not make the SID forward the packet.
#define GR_SRV6_ULP_DEFAULT_BITMAP {[IPPROTO_ICMPV6 / 8] = (1u << (IPPROTO_ICMPV6 % 8))}

static inline void gr_srv6_ulp_allow(uint8_t bitmap[GR_SRV6_ULP_BITMAP_LEN], uint8_t proto) {
	bitmap[proto / 8] |= (uint8_t)(1u << (proto % 8));
}

static inline bool
gr_srv6_ulp_allowed(const uint8_t bitmap[GR_SRV6_ULP_BITMAP_LEN], uint8_t proto) {
	return (bitmap[proto / 8] >> (proto % 8)) & 1;
}

// An all-zero bitmap means the SID was configured without an explicit
// allow-list and gets the default one.
static inline void gr_srv6_ulp_normalize(uint8_t bitmap[GR_SRV6_ULP_BITMAP_LEN]) {
	for (unsigned i = 0; i < GR_SRV6_ULP_BITMAP_LEN; i++)
		if (bitmap[i] != 0)
			return;
	gr_srv6_ulp_allow(bitmap, IPPROTO_ICMPV6);
}

// Per-SID counters. The daemon increments them on every packet it accepts
// for the SID; clients must ignore them in requests.
struct gr_srv6_sid_stats {
	uint64_t packets;
	uint64_t bytes;
};

// SRv6 local nexthop information for Local SID processing.
// Used with GR_NH_T_SR6_LOCAL nexthops via GR_NH_ADD from gr_infra.h.
struct gr_nexthop_info_srv6_local {
	uint16_t out_vrf_id;
	gr_srv6_behavior_t behavior;
	gr_srv6_flags_t flags;
	uint8_t block_bits; // Locator-block length in bits (default 32).
	uint8_t csid_bits; // Compressed SID length in bits (default 16).
	// Upper-layer headers delivered locally (default: ICMPv6 only). Used
	// by every behavior that can receive a packet which is not the family
	// it decapsulates, including the decapsulation ones (RFC 8986 section
	// 4.1.1).
	uint8_t ulp_bitmap[GR_SRV6_ULP_BITMAP_LEN];
	struct rte_ipv6_addr endx_addr; // END_X: L3 nexthop address (on base iface).
	struct gr_srv6_sid_stats stats; // Read-only, filled by the daemon.
};
