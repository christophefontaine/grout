// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#pragma once

#include "iface.h"
#include "ip6.h"
#include "nexthop.h"

#include <gr_srv6.h>

// Internal SRv6 L2 service port info structure.
GR_IFACE_INFO(GR_IFACE_TYPE_SR6, iface_info_sr6, {
	BASE(gr_iface_info_sr6);
});

//
// srv6 local data stored in nexthop priv
//
GR_NH_TYPE_INFO(GR_NH_T_SR6_LOCAL, nexthop_info_srv6_local, {
	BASE(gr_nexthop_info_srv6_local);
	struct nexthop *l3_nh; // END.X: resolved L3 nexthop (referenced)
	uint16_t prev_iface_id; // only used to maintain hash table consistency
});

typedef enum : uint8_t {
	SR_ENCAP_F_SRC = GR_BIT8(0),
} sr_encap_flags_t;

//
// srv6 encap data is allocated dynamically.
// A pointer to it is stored in nexthop priv.
//
GR_NH_TYPE_INFO(GR_NH_T_SR6_OUTPUT, nexthop_info_srv6_output, {
	gr_srv6_encap_behavior_t encap;
	sr_encap_flags_t flags;
	uint16_t n_seglist;
	struct rte_ipv6_addr *seglist;
	struct rte_ipv6_addr encap_src;
	// Datapath cache: immutable encapsulation snapshot with one
	// pre-built outer header slot per datapath worker, published with
	// a single pointer store and replaced under RCU on reconfig.
	struct sr6_output_cache *cache;
});

// Pre-built H.Encaps outer header slot. The worker owning the slot is
// its only writer. The two bytes that depend on the inner packet
// family (the outer protocol, and the SRH next header when present)
// are not part of the template: they are patched per packet, so a
// single slot serves both inner families.
struct sr6_l3_encap_tpl {
	const struct nexthop *nh; // underlay nexthop (NULL when encap_src is set)
	uint32_t gen; // sr6_output_tpl_gen when the header was built
	uint16_t hdr_len; // 0 = invalid
	// The header is written and read through IPv6/SRH structure
	// pointers (which carry 32-bit fields) and memcpy'd to the mbuf
	// headroom: it must be naturally aligned.
	uint8_t hdr[] __attribute__((aligned(8)));
};

// Immutable encapsulation snapshot published to the datapath with the
// nexthop: the config fields, the segment list and the per-worker
// template slots live in a single block so a worker can never observe
// a mix of an old and a new configuration (the header size depends on
// the segment list length). The slots are indexed by rte_lcore_id();
// n_slots is the lcore count when the block was built.
struct sr6_output_cache {
	gr_srv6_encap_behavior_t encap;
	sr_encap_flags_t flags;
	uint16_t n_seglist;
	uint16_t n_slots;
	uint32_t stride; // slot stride in bytes
	uint32_t slots_off; // byte offset of the slots array
	struct rte_ipv6_addr encap_src;
	const struct rte_ipv6_addr *seglist; // points to the segment list below
	/* struct rte_ipv6_addr seglist[n_seglist]; */
	/* struct sr6_l3_encap_tpl slots[n_slots]; */
};

// Bumped when the tunnel source or an underlay address changes: the
// cached headers embed the source address resolved at build time.
extern uint32_t sr6_output_tpl_gen;

extern struct nexthop *tunsrc_nh;
static inline const struct nexthop *
sr_tunsrc_get(uint16_t iface_id, const struct rte_ipv6_addr *dst) {
	return tunsrc_nh ? tunsrc_nh : addr6_get_preferred(iface_id, dst);
}
