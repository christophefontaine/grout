// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#pragma once

#include "ip6.h"
#include "nexthop.h"

#include <gr_srv6.h>

#include <stdatomic.h>

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

// The encapsulation config lives in the dynamically allocated
// sr6_output_cache block: the nexthop priv only holds the pointer.
GR_NH_TYPE_INFO(GR_NH_T_SR6_OUTPUT, nexthop_info_srv6_output, {
	struct sr6_output_cache *cache;
});

// Wire size of the outer encapsulation header for a segment list of n
// segments: the outer IPv6 header plus the SRH carrying the list.
#define SR6_ENCAP_HDR_CAP(n)                                                                    \
	(sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ipv6_routing_ext)                      \
	 + (n) * sizeof(struct rte_ipv6_addr))

// Pre-built H.Encaps outer header slot. The worker owning the slot is
// its only writer. The only byte that depends on the inner packet
// family (the SRH next header when present, the outer protocol
// otherwise) is not part of the template: it is patched per packet, so
// a single slot serves both inner families.
struct sr6_l3_encap_tpl {
	uint32_t gen; // sr6_output_tpl_gen when the header was built
	uint16_t iface_id; // underlay egress iface (unused when encap_src is set)
	uint16_t hdr_len;
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
	uint32_t slots_off; // byte offset of the slot array
	struct rte_ipv6_addr encap_src;
	// Trailing variable-length part: the segment list (n_seglist
	// addresses), then n_slots template slots of stride bytes each.
	struct rte_ipv6_addr seglist[] __attribute__((aligned(8)));
};

// Byte offset of the per-worker slot array, past the segment list.
// Stored in the cache at import: deriving it per packet would cost a
// handful of operations on the hot path. Both the offset and the slot
// stride are cache line aligned so that two workers never write in the
// same cache line when they rebuild their slot.
static inline size_t sr6_output_slots_off(uint16_t n_seglist) {
	return RTE_ALIGN(
		offsetof(struct sr6_output_cache, seglist) + n_seglist * sizeof(struct rte_ipv6_addr),
		RTE_CACHE_LINE_SIZE
	);
}

// The per-worker header slot of a snapshot (lcore must be < n_slots).
static inline struct sr6_l3_encap_tpl *
sr6_output_slot(const struct sr6_output_cache *cache, uint32_t lcore) {
	return (struct sr6_l3_encap_tpl *)
		((uint8_t *)cache + cache->slots_off + lcore * cache->stride);
}

// Bumped when the tunnel source, an underlay address or the
// encapsulation config changes: the cached headers embed state
// resolved at build time. Atomic with release/acquire ordering: the
// stores publishing the new state are ordered before the bump, and a
// worker that observes the new generation sees them.
extern _Atomic(uint32_t) sr6_output_tpl_gen;

static inline void sr6_output_tpl_invalidate(void) {
	atomic_fetch_add_explicit(&sr6_output_tpl_gen, 1, memory_order_release);
}

extern _Atomic(struct nexthop *) tunsrc_nh;
static inline const struct nexthop *
sr_tunsrc_get(uint16_t iface_id, const struct rte_ipv6_addr *dst) {
	const struct nexthop *nh = atomic_load_explicit(&tunsrc_nh, memory_order_acquire);
	return nh ? nh : addr6_get_preferred(iface_id, dst);
}
