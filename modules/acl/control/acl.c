// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#include "acl.h"
#include "config.h"
#include "event.h"
#include "iface.h"
#include "log.h"
#include "module.h"
#include "rcu.h"
#include "vec.h"

#include <gr_acl.h>

#include <rte_hash.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

LOG_TYPE("acl");

struct acl_entry_key {
	uint32_t set_id;
	uint32_t entry_id;
};

static struct rte_hash *acl_sets; // uint32_t set_id → struct acl_set *
static struct rte_hash *acl_entries; // struct acl_entry_key → struct acl_entry *
static struct rte_hash *acl_filters; // uint32_t filter_id → struct acl_filter *

// Rolling counters for auto allocated ids, contexts and filter
// priorities. Ids are sparse: user assigned ids can be any non zero
// value, collisions are resolved by skipping.
static uint32_t acl_next_id = 1;
static uint32_t acl_ctx_seq;
static uint32_t acl_filter_seq;

// Current compiled generation, control plane only. The dataplane reaches
// the contexts through the per interface RCU pointers.
static struct acl_generation {
	struct acl_class **classes;
	uint32_t n_classes;
	struct acl_result *results; // index 0 unused (no match)
	uint32_t n_results;
} *acl_gen;

// ---------------------------------------------------------------------------
// storage helpers

static struct rte_hash *acl_hash_new(const char *name, size_t key_len, uint32_t entries) {
	struct rte_hash_parameters params = {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.key_len = key_len,
		.entries = entries,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
	};
	struct rte_hash *h = rte_hash_create(&params);

	if (h == NULL) {
		errno = rte_errno;
		errno_log(errno, name);
	}
	return h;
}

// Allocate an unused id. key is a scratch hash key in which the id is
// stored at id_ofs: this checks for collisions against composite keys
// (e.g. struct acl_entry_key) as well as plain id keys. On success, the
// allocated id is written at id_ofs in key.
static int acl_id_alloc(struct rte_hash *hash, void *key, size_t id_ofs) {
	for (uint32_t i = 0; i < UINT32_MAX - 1; i++) {
		uint32_t candidate;

		if (acl_next_id == 0 || acl_next_id == UINT32_MAX)
			acl_next_id = 1;
		candidate = acl_next_id++;
		memcpy((uint8_t *)key + id_ofs, &candidate, sizeof(candidate));
		if (rte_hash_lookup(hash, key) < 0)
			return 0;
	}
	return errno_set(ENOSPC);
}

// ---------------------------------------------------------------------------
// rte_acl compilation
//
// Each (filter, set entry) pair is flattened into one rte_acl rule: the
// entry prefixes become masked address fields, the entry ports and the
// filter scalars become range fields. Rules are grouped per (address
// family, interface) into one rte_acl context published on the matching
// struct iface through an RCU protected pointer.

// One fragment criteria expansion: a rule must be duplicated when the
// criteria is an OR (e.g. "is a fragment" = MF set OR offset > 0).
struct acl_frag_spec {
	uint8_t value; // frag_flags field value
	uint8_t mask; // frag_flags field mask
	uint16_t off_lo; // frag_offset range
	uint16_t off_hi;
};

#define ACL_FRAG_OFF_MAX 0x1fff
#define ACL_MAX_SPECS 8

// Filter scalar criteria that rte_acl cannot express directly (no
// negation): inverse ranges are split into several rule variants.
struct acl_variant {
	uint16_t pkt_lo, pkt_hi;
	uint8_t dscp_lo, dscp_hi;
	uint32_t flow_lo, flow_hi;
	struct acl_frag_spec frag;
};

#define ACL_MAX_VARIANTS 16

// Rules of one (address family, interface) group.
struct acl_group {
	struct rte_acl_rule *rules; // RTE_ACL_RULE_SZ(fld_num) each
	uint32_t n_rules;
	uint32_t cap;
	uint32_t fld_num;
	bool l4; // at least one rule uses layer 4 fields
};

static const struct rte_acl_field_def acl_defs4[ACL4_F_COUNT] = {
	[ACL4_F_PROTO] = {RTE_ACL_FIELD_TYPE_RANGE, 1, ACL4_F_PROTO, 0, 0},
	[ACL4_F_DSCP] = {RTE_ACL_FIELD_TYPE_RANGE, 1, ACL4_F_DSCP, 0, 1},
	[ACL4_F_FRAG_FLAGS] = {RTE_ACL_FIELD_TYPE_BITMASK, 1, ACL4_F_FRAG_FLAGS, 0, 2},
	[ACL4_F_FRAG_OFFSET] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL4_F_FRAG_OFFSET, 1, 4},
	[ACL4_F_SRC] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL4_F_SRC, 2, 8},
	[ACL4_F_DST] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL4_F_DST, 3, 12},
	[ACL4_F_L4_A] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL4_F_L4_A, 4, 16},
	[ACL4_F_L4_B] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL4_F_L4_B, 4, 18},
	[ACL4_F_TCP_FLAGS] = {RTE_ACL_FIELD_TYPE_BITMASK, 1, ACL4_F_TCP_FLAGS, 5, 20},
	[ACL4_F_PKT_LEN] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL4_F_PKT_LEN, 5, 22},
};

static const struct rte_acl_field_def acl_defs6[ACL6_F_COUNT] = {
	[ACL6_F_PROTO] = {RTE_ACL_FIELD_TYPE_RANGE, 1, ACL6_F_PROTO, 0, 0},
	[ACL6_F_DSCP] = {RTE_ACL_FIELD_TYPE_RANGE, 1, ACL6_F_DSCP, 0, 1},
	[ACL6_F_FLOW_LABEL] = {RTE_ACL_FIELD_TYPE_RANGE, 4, ACL6_F_FLOW_LABEL, 1, 4},
	[ACL6_F_SRC + 0] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_SRC + 0, 2, 8},
	[ACL6_F_SRC + 1] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_SRC + 1, 3, 12},
	[ACL6_F_SRC + 2] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_SRC + 2, 4, 16},
	[ACL6_F_SRC + 3] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_SRC + 3, 5, 20},
	[ACL6_F_DST + 0] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_DST + 0, 6, 24},
	[ACL6_F_DST + 1] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_DST + 1, 7, 28},
	[ACL6_F_DST + 2] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_DST + 2, 8, 32},
	[ACL6_F_DST + 3] = {RTE_ACL_FIELD_TYPE_MASK, 4, ACL6_F_DST + 3, 9, 36},
	[ACL6_F_L4_A] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL6_F_L4_A, 10, 40},
	[ACL6_F_L4_B] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL6_F_L4_B, 10, 42},
	[ACL6_F_TCP_FLAGS] = {RTE_ACL_FIELD_TYPE_BITMASK, 1, ACL6_F_TCP_FLAGS, 11, 44},
	[ACL6_F_PKT_LEN] = {RTE_ACL_FIELD_TYPE_RANGE, 2, ACL6_F_PKT_LEN, 11, 46},
};

// Expand the FRR fragment criteria into rule fragments. Returns the
// number of specs, or -1 for unsupported combinations (the inverse of an
// OR of several bits).
static int acl_frag_specs(uint8_t fragment, bool inverse, struct acl_frag_spec *specs) {
	uint32_t n_specs = 0;

	if (fragment == 0) {
		specs[0] = (struct acl_frag_spec) {.off_lo = 0, .off_hi = ACL_FRAG_OFF_MAX};
		return 1;
	}

	for (uint8_t bit = 0; bit < 4; bit++) {
		uint8_t frag = 1 << bit; // DONT, IS, FIRST, LAST
		struct acl_frag_spec *s;

		if (!(fragment & frag))
			continue;

		s = &specs[n_specs];
		*s = (struct acl_frag_spec) {.off_lo = 0, .off_hi = ACL_FRAG_OFF_MAX};

		switch (frag) {
		case GR_ACL_FRAGMENT_DONT:
			// DF bit set (or clear when inverse)
			s->value = inverse ? 0 : ACL_FRAG_DONT;
			s->mask = ACL_FRAG_DONT;
			n_specs++;
			break;
		case GR_ACL_FRAGMENT_IS:
			if (inverse) {
				// not a fragment: MF clear AND offset 0
				s->mask = ACL_FRAG_MORE;
				s->off_hi = 0;
				n_specs++;
			} else {
				// a fragment: MF set OR offset > 0
				s->value = ACL_FRAG_MORE;
				s->mask = ACL_FRAG_MORE;
				s++;
				s->off_lo = 1;
				n_specs += 2;
			}
			break;
		case GR_ACL_FRAGMENT_FIRST:
			if (inverse) {
				// not a first fragment: offset > 0 OR MF clear
				s->off_lo = 1;
				s++;
				s->mask = ACL_FRAG_MORE;
				n_specs += 2;
			} else {
				// first fragment: MF set AND offset 0
				s->value = ACL_FRAG_MORE;
				s->mask = ACL_FRAG_MORE;
				s->off_hi = 0;
				n_specs++;
			}
			break;
		case GR_ACL_FRAGMENT_LAST:
			if (inverse) {
				// not a last fragment: offset 0 OR MF set
				s->off_hi = 0;
				s++;
				s->value = ACL_FRAG_MORE;
				s->mask = ACL_FRAG_MORE;
				n_specs += 2;
			} else {
				// last fragment: MF clear AND offset > 0
				s->mask = ACL_FRAG_MORE;
				s->off_lo = 1;
				n_specs++;
			}
			break;
		}

		if (n_specs > ACL_MAX_SPECS)
			return -1;
		// The inverse of an OR of several bits is not expressible.
		if (inverse && n_specs > 1)
			return -1;
	}

	return n_specs;
}

// Replicate the first n variants n_frag times and assign each replica a
// fragment spec.
static void acl_variants_expand_frag(
	struct acl_variant *variants,
	uint32_t n,
	const struct acl_frag_spec *frag,
	uint32_t n_frag
) {
	for (uint32_t v = n; v-- > 0;)
		for (uint32_t i = n_frag; i-- > 0;)
			variants[v * n_frag + i] = variants[v];
	for (uint32_t v = 0; v < n; v++)
		for (uint32_t i = 0; i < n_frag; i++)
			variants[v * n_frag + i].frag = frag[i];
}

// Load a little endian scalar of 1, 2 or 4 bytes.
static uint64_t acl_scalar_load(const void *p, size_t size) {
	switch (size) {
	case 1:
		return *(const uint8_t *)p;
	case 2:
		return *(const uint16_t *)p;
	default:
		return *(const uint32_t *)p;
	}
}

// Store a little endian scalar of 1, 2 or 4 bytes.
static void acl_scalar_store(void *p, size_t size, uint64_t v) {
	switch (size) {
	case 1:
		*(uint8_t *)p = v;
		break;
	case 2:
		*(uint16_t *)p = v;
		break;
	default:
		*(uint32_t *)p = v;
		break;
	}
}

// Split the n variants around the scalar range [lo..hi] stored at
// lo_ofs/hi_ofs (scalar of 1, 2 or 4 bytes): the inverse of the range is
// the union of [0..lo-1] and [hi+1..max], so the variants are duplicated
// when both sides are non empty, the first half getting the lower side
// and the second half the upper side. Returns the new variant count or
// -1 with ENOTSUP when the table is full or the range covers everything
// (the inverse would match nothing).
static int acl_variant_split_inverse(
	struct acl_variant *variants,
	uint32_t n,
	size_t lo_ofs,
	size_t hi_ofs,
	size_t size
) {
	uint64_t max = size == 1 ? UINT8_MAX : size == 2 ? UINT16_MAX : UINT32_MAX;
	uint64_t lo = acl_scalar_load((const uint8_t *)variants + lo_ofs, size);
	uint64_t hi = acl_scalar_load((const uint8_t *)variants + hi_ofs, size);
	bool lower = lo > 0, upper = hi < max;
	uint64_t vlo, vhi;

	if (!lower && !upper)
		return errno_set(ENOTSUP); // the inverse matches nothing
	if (lower && upper) {
		if ((uint64_t)n * 2 > ACL_MAX_VARIANTS)
			return errno_set(ENOTSUP);
		// iterate downward so the copies do not overwrite sources
		for (uint32_t v = n; v-- > 0;) {
			variants[2 * v] = variants[v];
			variants[2 * v + 1] = variants[v];
		}
		n *= 2;
	}

	for (uint32_t v = 0; v < n; v++) {
		// when both sides are non empty, the first half of the
		// variants carries the lower side and the second half the
		// upper side
		if (lower && (!upper || v < n / 2)) {
			vlo = 0;
			vhi = lo - 1;
		} else {
			vlo = hi + 1;
			vhi = max;
		}
		acl_scalar_store((uint8_t *)&variants[v] + lo_ofs, size, vlo);
		acl_scalar_store((uint8_t *)&variants[v] + hi_ofs, size, vhi);
	}

	return n;
}

// Expand the filter scalar criteria into rule variants, splitting the
// inverse ranges that rte_acl cannot negate. Returns the variant count or
// -1 on unsupported combinations.
static int acl_variants(const struct gr_acl_filter *f, bool v6, struct acl_variant *variants) {
	struct acl_frag_spec frag[ACL_MAX_SPECS];
	uint32_t bm = f->match_bm;
	uint32_t n = 1;
	int n_frag;

	variants[0] = (struct acl_variant) {
		.pkt_lo = 0,
		.pkt_hi = UINT16_MAX,
		.dscp_lo = 0,
		.dscp_hi = UINT8_MAX,
		.flow_lo = 0,
		.flow_hi = UINT32_MAX,
	};

	if (f->pkt_len_min != 0 || f->pkt_len_max != 0) {
		uint16_t lo = f->pkt_len_min;
		uint16_t hi = f->pkt_len_max != 0 ? f->pkt_len_max : UINT16_MAX;

		for (uint32_t v = 0; v < n; v++) {
			variants[v].pkt_lo = lo;
			variants[v].pkt_hi = hi;
		}
		if (bm & GR_ACL_MATCH_PKT_LEN_INVERSE) {
			n = acl_variant_split_inverse(
				variants,
				n,
				offsetof(struct acl_variant, pkt_lo),
				offsetof(struct acl_variant, pkt_hi),
				sizeof(uint16_t)
			);
			if (n < 0)
				return n;
		}
	}

	if ((bm & GR_ACL_MATCH_DSCP) || (bm & GR_ACL_MATCH_DSCP_INVERSE)) {
		for (uint32_t v = 0; v < n; v++) {
			variants[v].dscp_lo = f->dscp;
			variants[v].dscp_hi = f->dscp;
		}
		if (bm & GR_ACL_MATCH_DSCP_INVERSE) {
			n = acl_variant_split_inverse(
				variants,
				n,
				offsetof(struct acl_variant, dscp_lo),
				offsetof(struct acl_variant, dscp_hi),
				sizeof(uint8_t)
			);
			if (n < 0)
				return n;
		}
	}

	if (v6 && ((bm & GR_ACL_MATCH_FLOW_LABEL) || (bm & GR_ACL_MATCH_FLOW_LABEL_INVERSE))) {
		for (uint32_t v = 0; v < n; v++) {
			variants[v].flow_lo = f->flow_label;
			variants[v].flow_hi = f->flow_label;
		}
		if (bm & GR_ACL_MATCH_FLOW_LABEL_INVERSE) {
			n = acl_variant_split_inverse(
				variants,
				n,
				offsetof(struct acl_variant, flow_lo),
				offsetof(struct acl_variant, flow_hi),
				sizeof(uint32_t)
			);
			if (n < 0)
				return n;
		}
	}

	n_frag = acl_frag_specs(f->fragment, (bm & GR_ACL_MATCH_FRAGMENT_INVERSE) != 0, frag);
	if (n_frag < 0)
		return errno_set(ENOTSUP);
	if (n * (uint32_t)n_frag > ACL_MAX_VARIANTS)
		return errno_set(ENOTSUP);

	acl_variants_expand_frag(variants, n, frag, n_frag);

	return n * n_frag;
}

// Set the address fields of a rule from a gr_acl_net prefix.
//
// rte_acl reads the rule's value from MSB to LSB and compares against the
// input bytes in order. The input bytes are in network order (big
// endian), so the rule's value must be the big endian interpretation of
// the address bytes: byte swap the raw address on little endian hosts.
// mask_range holds the prefix length.
static void acl_rule_set_net(
	struct rte_acl_rule *rule,
	uint32_t first_field,
	const struct gr_acl_net *net,
	addr_family_t af
) {
	uint32_t n_fields = af == GR_AF_IP6 ? 4 : 1;

	if (net->af != af || net->prefixlen == 0) {
		// wildcard
		for (uint32_t i = 0; i < n_fields; i++) {
			rule->field[first_field + i].value.u32 = 0;
			rule->field[first_field + i].mask_range.u32 = 0;
		}
		return;
	}

	if (af == GR_AF_IP4) {
		// net->ip4 holds the raw 4 bytes as a LE u32; rte_acl expects
		// the BE interpretation for the comparison against the key.
		rule->field[first_field].value.u32 = rte_be_to_cpu_32(net->ip4);
		rule->field[first_field].mask_range.u32 = net->prefixlen;
		return;
	}

	// IPv6: one u32 field per 32 bit chunk, each with its prefix length
	// slice (same layout as the DPDK l3fwd IPv6 ACL rules).
	for (uint32_t i = 0; i < n_fields; i++) {
		uint32_t value;

		memcpy(&value, &net->ip6.a[4 * i], sizeof(value));
		rule->field[first_field + i].value.u32 = rte_be_to_cpu_32(value);
		rule->field[first_field + i].mask_range.u32 = net->prefixlen > 32 * i ?
			RTE_MIN(net->prefixlen - 32 * i, 32) :
			0;
	}
}

// Set the port fields of a rule from the entry ports. For ICMP filters,
// the entry ports carry the type and code packed in the same key bytes as
// the source port.
static void acl_rule_set_ports(
	struct acl_group *g,
	struct rte_acl_rule *r,
	uint32_t f_l4a,
	uint32_t f_l4b,
	const struct acl_entry *e,
	bool icmp
) {
	uint16_t lo = e->src_port_min;
	uint16_t hi = e->src_port_max != 0 ? e->src_port_max : lo;

	if (icmp) {
		uint16_t code = e->dst_port_min;

		if (lo == 0) {
			// no type constraint: the code cannot be matched on
			// its own, ignore it (rare, fails closed)
			hi = UINT16_MAX;
		} else if (code == 0) {
			// type [lo..hi], any code
			lo <<= 8;
			hi = (hi << 8) | UINT8_MAX;
		} else {
			// exact type and code
			lo = (lo << 8) | code;
			hi = lo;
		}
	}
	// A wildcard is [0..65535], not [0..0] which means "exactly zero".
	if (lo == 0 && hi == 0)
		hi = UINT16_MAX;
	r->field[f_l4a].value.u16 = lo;
	r->field[f_l4a].mask_range.u16 = hi;

	if (icmp) {
		// the code is folded into l4_a
		r->field[f_l4b].value.u16 = 0;
		r->field[f_l4b].mask_range.u16 = UINT16_MAX;
	} else {
		lo = e->dst_port_min;
		hi = e->dst_port_max != 0 ? e->dst_port_max : lo;
		if (lo == 0 && hi == 0)
			hi = UINT16_MAX;
		r->field[f_l4b].value.u16 = lo;
		r->field[f_l4b].mask_range.u16 = hi;
	}

	if (e->src_port_min != 0 || e->dst_port_min != 0 || icmp)
		g->l4 = true;
}

static struct rte_acl_rule *acl_group_new_rule(struct acl_group *g) {
	size_t rule_size = RTE_ACL_RULE_SZ(g->fld_num);
	struct rte_acl_rule *rules;

	if (g->n_rules == g->cap) {
		g->cap = g->cap != 0 ? g->cap * 2 : 8;
		rules = realloc(g->rules, g->cap * rule_size);
		if (rules == NULL) {
			g->cap /= 2;
			return NULL;
		}
		g->rules = rules;
	}
	return (struct rte_acl_rule *)((uint8_t *)g->rules + g->n_rules * rule_size);
}

// Emit one rule per (variant, set entry) into the group.
static int acl_group_emit(
	struct acl_group *g,
	const struct gr_acl_filter *f,
	uint32_t seq,
	uint32_t result_idx,
	const struct acl_set *set,
	const struct acl_variant *variants,
	uint32_t n_variants
) {
	const struct acl_variant *v;
	const struct acl_entry *e;
	bool icmp = (f->match_bm & GR_ACL_MATCH_ICMP) != 0;
	uint32_t f_proto, f_src, f_dst, f_l4a, f_l4b;
	bool v6 = f->af == GR_AF_IP6;

	if (v6) {
		f_proto = ACL6_F_PROTO;
		f_src = ACL6_F_SRC;
		f_dst = ACL6_F_DST;
		f_l4a = ACL6_F_L4_A;
		f_l4b = ACL6_F_L4_B;
	} else {
		f_proto = ACL4_F_PROTO;
		f_src = ACL4_F_SRC;
		f_dst = ACL4_F_DST;
		f_l4a = ACL4_F_L4_A;
		f_l4b = ACL4_F_L4_B;
	}

	for (uint32_t i = 0; i < n_variants; i++) {
		v = &variants[i];

		for (e = set->entries; e != NULL; e = e->next) {
			struct rte_acl_rule *r = acl_group_new_rule(g);
			uint8_t proto;

			if (r == NULL)
				return errno_set(ENOMEM);
			memset(r, 0, RTE_ACL_RULE_SZ(g->fld_num));

			r->data.userdata = result_idx;
			// Larger priorities win: the newest filter wins ties.
			r->data.priority = (seq % RTE_ACL_MAX_PRIORITY) + 1;
			r->data.category_mask = 1;

			// The proto constraints of the filter and of the entry
			// must both hold.
			if (f->match_bm & GR_ACL_MATCH_PROTOCOL) {
				if (e->proto != 0 && e->proto != f->proto)
					continue; // can never match
				proto = f->proto;
			} else if (e->proto != 0) {
				proto = e->proto;
			} else {
				proto = 0;
			}
			// For a RANGE field, mask_range holds the high bound of
			// the range: an exact protocol match, or a wildcard when
			// neither the filter nor the entry constrains it.
			r->field[f_proto].value.u8 = proto;
			r->field[f_proto].mask_range.u8 = proto != 0 ? proto : UINT8_MAX;

			acl_rule_set_ports(g, r, f_l4a, f_l4b, e, icmp);
			acl_rule_set_net(r, f_src, &e->src, f->af);
			acl_rule_set_net(r, f_dst, &e->dst, f->af);

			if (v6) {
				r->field[ACL6_F_DSCP].value.u8 = v->dscp_lo;
				r->field[ACL6_F_DSCP].mask_range.u8 = v->dscp_hi;
				r->field[ACL6_F_FLOW_LABEL].value.u32 = v->flow_lo;
				r->field[ACL6_F_FLOW_LABEL].mask_range.u32 = v->flow_hi;
				r->field[ACL6_F_TCP_FLAGS].value.u8 = f->tcp_flags & f->tcp_mask;
				r->field[ACL6_F_TCP_FLAGS].mask_range.u8 = f->tcp_mask;
				r->field[ACL6_F_PKT_LEN].value.u16 = v->pkt_lo;
				r->field[ACL6_F_PKT_LEN].mask_range.u16 = v->pkt_hi;
			} else {
				r->field[ACL4_F_DSCP].value.u8 = v->dscp_lo;
				r->field[ACL4_F_DSCP].mask_range.u8 = v->dscp_hi;
				r->field[ACL4_F_TCP_FLAGS].value.u8 = f->tcp_flags & f->tcp_mask;
				r->field[ACL4_F_TCP_FLAGS].mask_range.u8 = f->tcp_mask;
				r->field[ACL4_F_PKT_LEN].value.u16 = v->pkt_lo;
				r->field[ACL4_F_PKT_LEN].mask_range.u16 = v->pkt_hi;
				r->field[ACL4_F_FRAG_FLAGS].value.u8 = v->frag.value;
				r->field[ACL4_F_FRAG_FLAGS].mask_range.u8 = v->frag.mask;
				r->field[ACL4_F_FRAG_OFFSET].value.u16 = v->frag.off_lo;
				r->field[ACL4_F_FRAG_OFFSET].mask_range.u16 = v->frag.off_hi;
			}
			if (f->tcp_mask != 0)
				g->l4 = true;

			g->n_rules++;
		}
	}

	return 0;
}

static void acl_generation_free(struct acl_generation *gen) {
	if (gen == NULL)
		return;
	for (uint32_t i = 0; i < gen->n_classes; i++) {
		rte_acl_free(gen->classes[i]->acl);
		free(gen->classes[i]);
	}
	free(gen->classes);
	free(gen->results);
	free(gen);
}

static void acl_group_fini(struct acl_group *groups, uint32_t n) {
	if (groups == NULL)
		return;
	for (uint32_t i = 0; i < n; i++)
		free(groups[i].rules);
	free(groups);
}

// Build the rte_acl context of a non empty group. Returns the class or
// NULL on failure.
static struct acl_class *acl_class_build(struct acl_group *g, int af, uint16_t ifid) {
	struct rte_acl_config cfg = {.num_categories = 1};
	struct acl_class *class;
	char name[RTE_ACL_NAMESIZE];
	struct rte_acl_ctx *ctx;

	snprintf(name, sizeof(name), "acl%u-%d-%u", acl_ctx_seq++, af, ifid);
	ctx = rte_acl_create(&(struct rte_acl_param) {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.rule_size = RTE_ACL_RULE_SZ(g->fld_num),
		.max_rule_num = g->n_rules * 2 + 16,
	});
	if (ctx == NULL) {
		LOG(ERR, "rte_acl_create(%s): %s", name, rte_strerror(rte_errno));
		return NULL;
	}
	if (af == 0) {
		cfg.num_fields = ACL4_F_COUNT;
		memcpy(cfg.defs, acl_defs4, sizeof(acl_defs4));
	} else {
		cfg.num_fields = ACL6_F_COUNT;
		memcpy(cfg.defs, acl_defs6, sizeof(acl_defs6));
	}

	if (rte_acl_add_rules(ctx, g->rules, g->n_rules) < 0 || rte_acl_build(ctx, &cfg) < 0) {
		LOG(ERR, "cannot build %s: %s", name, rte_strerror(rte_errno));
		rte_acl_free(ctx);
		return NULL;
	}

	class = calloc(1, sizeof(*class));
	if (class == NULL) {
		LOG(ERR, "cannot allocate the ACL class: %s", strerror(errno));
		rte_acl_free(ctx);
		return NULL;
	}
	class->acl = ctx;
	class->l4 = g->l4;

	return class;
}

// Rebuild the classification contexts from the control plane state,
// publish them through the per interface RCU pointers and free the
// previous generation once the dataplane workers are done with it.
static void acl_recompile(void) {
	uint32_t n_filters = rte_hash_count(acl_filters);
	struct acl_class **class_map[2] = {NULL, NULL};
	struct acl_generation *old = acl_gen, *gen;
	struct acl_group *groups[2] = {NULL, NULL};
	// class_map[af][iface_id] → published class, NULL when no rule
	struct acl_filter *filter = NULL;
	uint16_t n_ifaces = gr_config.max_ifaces;
	uint32_t next = 0;
	void *data;
	const void *key;

	gen = calloc(1, sizeof(*gen));
	if (gen == NULL) {
		LOG(ERR, "cannot allocate the ACL generation: %s", strerror(errno));
		return;
	}

	if (n_filters > 0) {
		gen->n_results = n_filters + 1;
		gen->results = calloc(gen->n_results, sizeof(*gen->results));
		groups[0] = calloc(n_ifaces, sizeof(*groups[0]));
		groups[1] = calloc(n_ifaces, sizeof(*groups[1]));
		class_map[0] = calloc(n_ifaces, sizeof(*class_map[0]));
		class_map[1] = calloc(n_ifaces, sizeof(*class_map[1]));
		if (gen->results == NULL || groups[0] == NULL || groups[1] == NULL
		    || class_map[0] == NULL || class_map[1] == NULL) {
			LOG(ERR, "cannot allocate the ACL generation: %s", strerror(ENOMEM));
			goto err;
		}

		// Flatten every filter into per (af, iface) rule groups.
		uint32_t result_idx = 1;
		while (rte_hash_iterate(acl_filters, &key, &data, &next) >= 0) {
			struct acl_variant variants[ACL_MAX_VARIANTS];
			struct acl_set *set = NULL;
			int n_variants, af;

			filter = data;
			gen->results[result_idx].stats = filter->stats;

			rte_hash_lookup_data(acl_sets, &filter->set_id, (void **)&set);
			if (set == NULL || set->n_entries == 0) {
				result_idx++;
				continue;
			}
			n_variants = acl_variants(&filter->base, filter->af == GR_AF_IP6, variants);
			if (n_variants < 0) {
				LOG(WARNING,
				    "filter %u skipped: %s",
				    filter->filter_id,
				    strerror(errno));
				result_idx++;
				continue;
			}

			af = filter->af == GR_AF_IP6;
			for (uint16_t j = 0; j < filter->n_ifaces; j++) {
				uint16_t ifid = filter->iface_ids[j];
				struct acl_group *g;
				if (ifid == 0 || ifid >= n_ifaces || iface_from_id(ifid) == NULL) {
					LOG(DEBUG,
					    "filter %u: no such interface %u",
					    filter->filter_id,
					    ifid);
					continue;
				}
				g = &groups[af][ifid];
				if (g->rules == NULL)
					*g = (struct acl_group) {
						.fld_num = af ? ACL6_F_COUNT : ACL4_F_COUNT,
					};
				if (acl_group_emit(
					    g,
					    &filter->base,
					    filter->seq,
					    result_idx,
					    set,
					    variants,
					    n_variants
				    )
				    < 0)
					LOG(WARNING,
					    "filter %u: %s",
					    filter->filter_id,
					    strerror(errno));
			}
			result_idx++;
		}

		// Build one rte_acl context per non empty group.
		for (int af = 0; af < 2; af++) {
			for (uint16_t ifid = 0; ifid < n_ifaces; ifid++) {
				struct acl_class **classes;
				struct acl_class *class;

				if (groups[af][ifid].rules == NULL)
					continue;
				class = acl_class_build(&groups[af][ifid], af, ifid);
				if (class == NULL)
					continue;
				class->results = gen->results;
				classes = realloc(
					gen->classes, (gen->n_classes + 1) * sizeof(*gen->classes)
				);
				if (classes == NULL) {
					LOG(ERR,
					    "cannot allocate the ACL classes: %s",
					    strerror(ENOMEM));
					rte_acl_free(class->acl);
					free(class);
					continue;
				}
				gen->classes = classes;
				gen->classes[gen->n_classes++] = class;
				class_map[af][ifid] = class;
			}
		}
	}

	// Publish: patch the per interface pointers, wait for the dataplane
	// to be done with the previous generation and free it.
	for (int af = 0; af < 2; af++) {
		struct iface *iface = NULL;

		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			if (class_map[af] != NULL)
				iface->acl[af] = class_map[af][iface->id];
			else
				iface->acl[af] = NULL;
		}
	}
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	acl_generation_free(old);
	acl_gen = gen;

	acl_group_fini(groups[0], n_ifaces);
	acl_group_fini(groups[1], n_ifaces);
	free(class_map[0]);
	free(class_map[1]);
	return;

err:
	acl_generation_free(gen);
	acl_group_fini(groups[0], n_ifaces);
	acl_group_fini(groups[1], n_ifaces);
	free(class_map[0]);
	free(class_map[1]);
}

// ---------------------------------------------------------------------------
// API handlers

static bool acl_net_valid(const struct gr_acl_net *net, addr_family_t af) {
	if (net->af == GR_AF_UNSPEC)
		return true;
	if (net->af != af)
		return false;
	if (af == GR_AF_IP4)
		return net->prefixlen <= 32;
	if (af == GR_AF_IP6)
		return net->prefixlen <= 128;
	return false;
}

static struct api_out acl_set_add(const void *request, struct api_ctx *) {
	const struct gr_acl_set_add_req *req = request;
	struct acl_set *set = NULL;
	uint32_t set_id;
	int ret;

	if (req->set.af != GR_AF_IP4 && req->set.af != GR_AF_IP6)
		return api_out(EINVAL, 0, NULL);
	if (req->set.type < GR_ACL_SET_NET_NET || req->set.type > GR_ACL_SET_NET)
		return api_out(EINVAL, 0, NULL);

	set_id = req->set.set_id;
	if (set_id != 0) {
		rte_hash_lookup_data(acl_sets, &set_id, (void **)&set);
		if (set != NULL) {
			if (!req->exist_ok)
				return api_out(EEXIST, 0, NULL);
			if (set->af != req->set.af)
				return api_out(EINVAL, 0, NULL);
			set->type = req->set.type;
			set->vrf_id = req->set.vrf_id;
			return api_out(0, 0, NULL);
		}
	} else if (acl_id_alloc(acl_sets, &set_id, 0) < 0) {
		return api_out(ENOSPC, 0, NULL);
	}

	set = calloc(1, sizeof(*set));
	if (set == NULL)
		return api_out(ENOMEM, 0, NULL);
	set->base = req->set;
	set->base.set_id = set_id;

	ret = rte_hash_add_key_data(acl_sets, &set->base.set_id, set);
	if (ret < 0) {
		free(set);
		return api_out(-ret, 0, NULL);
	}

	event_push(GR_EVENT_ACL_SET_ADD, set);
	return api_out(0, 0, NULL);
}

static struct api_out acl_set_del(const void *request, struct api_ctx *) {
	const struct gr_acl_set_del_req *req = request;
	struct acl_set *set = NULL;

	rte_hash_lookup_data(acl_sets, &req->set_id, (void **)&set);
	if (set == NULL) {
		if (req->missing_ok)
			return api_out(0, 0, NULL);
		return api_out(ENOENT, 0, NULL);
	}
	if (set->n_entries > 0 || set->n_filters > 0)
		return api_out(EBUSY, 0, NULL);

	rte_hash_del_key(acl_sets, &req->set_id);
	event_push(GR_EVENT_ACL_SET_DEL, set);
	free(set);
	return api_out(0, 0, NULL);
}

static struct api_out acl_set_list(const void *, struct api_ctx *ctx) {
	struct acl_set *set = NULL;
	uint32_t next = 0;
	const void *key;

	while (rte_hash_iterate(acl_sets, &key, (void **)&set, &next) >= 0)
		api_send(ctx, sizeof(set->base), &set->base);

	return api_out(0, 0, NULL);
}

static struct api_out acl_entry_add(const void *request, struct api_ctx *) {
	const struct gr_acl_entry_add_req *req = request;
	struct acl_entry *entry = NULL;
	struct acl_set *set = NULL;
	struct acl_entry_key key;
	int ret;

	rte_hash_lookup_data(acl_sets, &req->entry.set_id, (void **)&set);
	if (set == NULL)
		return api_out(ENOENT, 0, NULL);

	if (!acl_net_valid(&req->entry.src, set->af) || !acl_net_valid(&req->entry.dst, set->af))
		return api_out(EINVAL, 0, NULL);

	key = (struct acl_entry_key) {
		.set_id = req->entry.set_id,
		.entry_id = req->entry.entry_id,
	};
	if (key.entry_id != 0) {
		rte_hash_lookup_data(acl_entries, &key, (void **)&entry);
		if (entry != NULL) {
			if (!req->exist_ok)
				return api_out(EEXIST, 0, NULL);
			entry->base = req->entry;
			acl_recompile();
			return api_out(0, 0, NULL);
		}
	} else if (acl_id_alloc(acl_entries, &key, offsetof(struct acl_entry_key, entry_id)) < 0) {
		return api_out(ENOSPC, 0, NULL);
	}

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return api_out(ENOMEM, 0, NULL);
	entry->base = req->entry;
	entry->base.entry_id = key.entry_id;

	ret = rte_hash_add_key_data(acl_entries, &key, entry);
	if (ret < 0) {
		free(entry);
		return api_out(-ret, 0, NULL);
	}

	// Insert in the set list, most recent first.
	entry->next = set->entries;
	set->entries = entry;
	set->n_entries++;

	event_push(GR_EVENT_ACL_ENTRY_ADD, entry);
	acl_recompile();
	return api_out(0, 0, NULL);
}

static struct api_out acl_entry_del(const void *request, struct api_ctx *) {
	const struct gr_acl_entry_del_req *req = request;
	struct acl_entry *entry = NULL, **prev;
	struct acl_set *set = NULL;
	struct acl_entry_key key;

	key = (struct acl_entry_key) {
		.set_id = req->set_id,
		.entry_id = req->entry_id,
	};
	rte_hash_lookup_data(acl_entries, &key, (void **)&entry);
	if (entry == NULL) {
		if (req->missing_ok)
			return api_out(0, 0, NULL);
		return api_out(ENOENT, 0, NULL);
	}

	rte_hash_lookup_data(acl_sets, &req->set_id, (void **)&set);
	if (set != NULL) {
		prev = &set->entries;
		while (*prev != NULL && *prev != entry)
			prev = &(*prev)->next;
		if (*prev != NULL) {
			*prev = entry->next;
			set->n_entries--;
		}
	}

	rte_hash_del_key(acl_entries, &key);
	event_push(GR_EVENT_ACL_ENTRY_DEL, entry);
	free(entry);
	acl_recompile();
	return api_out(0, 0, NULL);
}

static struct api_out acl_entry_list(const void *request, struct api_ctx *ctx) {
	const struct gr_acl_entry_list_req *req = request;
	struct acl_entry *entry = NULL;
	uint32_t next = 0;
	const void *key;

	while (rte_hash_iterate(acl_entries, &key, (void **)&entry, &next) >= 0) {
		if (entry->set_id != req->set_id)
			continue;
		api_send(ctx, sizeof(entry->base), &entry->base);
	}

	return api_out(0, 0, NULL);
}

static struct api_out acl_filter_add(const void *request, struct api_ctx *ctx) {
	const struct gr_acl_filter_add_req *req = request;
	size_t len = sizeof(struct acl_filter) + req->filter.n_ifaces * sizeof(uint16_t);
	struct acl_filter *filter = NULL, *old = NULL;
	struct acl_set *set = NULL;
	uint32_t filter_id;
	int ret;

	// The interface id list extends past the fixed size request: check
	// that the client actually sent it before copying it in.
	if (ctx->header.payload_len < sizeof(*req) + req->filter.n_ifaces * sizeof(uint16_t))
		return api_out(EMSGSIZE, 0, NULL);

	if (req->filter.af != GR_AF_IP4 && req->filter.af != GR_AF_IP6)
		return api_out(EINVAL, 0, NULL);
	if (req->filter.match_bm & ~GR_ACL_MATCH_VALID)
		return api_out(EINVAL, 0, NULL);
	// TODO: support the GR_ACL_ACTION_MARK action (set the firewall mark
	// in the packet metadata and forward instead of dropping); requires
	// policy routing rules to consume the mark.
	if (req->filter.action != GR_ACL_ACTION_DROP)
		return api_out(EOPNOTSUPP, 0, NULL);

	rte_hash_lookup_data(acl_sets, &req->filter.set_id, (void **)&set);
	if (set == NULL)
		return api_out(ENOENT, 0, NULL);
	if (set->af != req->filter.af)
		return api_out(EINVAL, 0, NULL);

	filter_id = req->filter.filter_id;
	old = NULL;
	if (filter_id != 0) {
		rte_hash_lookup_data(acl_filters, &filter_id, (void **)&old);
		if (old != NULL && !req->exist_ok)
			return api_out(EEXIST, 0, NULL);
	} else if (acl_id_alloc(acl_filters, &filter_id, 0) < 0) {
		return api_out(ENOSPC, 0, NULL);
	}

	filter = calloc(1, len);
	if (filter == NULL)
		return api_out(ENOMEM, 0, NULL);
	filter->base = req->filter;
	filter->base.filter_id = filter_id;
	memcpy(filter->base.iface_ids,
	       req->filter.iface_ids,
	       req->filter.n_ifaces * sizeof(uint16_t));

	ret = rte_hash_add_key_data(acl_filters, &filter->base.filter_id, filter);

	if (ret < 0) {
		free(filter);
		return api_out(-ret, 0, NULL);
	}

	if (old != NULL) {
		// update in place: keep the stats block and the priority, and
		// fix the set reference counts if the set changed
		struct acl_set *old_set;

		rte_hash_lookup_data(acl_sets, &old->set_id, (void **)&old_set);
		if (old_set != NULL && old_set != set)
			old_set->n_filters--;
		if (old_set != set)
			set->n_filters++;
		filter->stats = old->stats;
		filter->seq = old->seq;
		free(old);
	} else {
		filter->stats = calloc(1, sizeof(*filter->stats));
		if (filter->stats == NULL) {
			rte_hash_del_key(acl_filters, &filter_id);
			free(filter);
			return api_out(ENOMEM, 0, NULL);
		}
		filter->seq = ++acl_filter_seq;
		set->n_filters++;
	}

	event_push(GR_EVENT_ACL_FILTER_ADD, filter);
	acl_recompile();
	return api_out(0, 0, NULL);
}

static struct api_out acl_filter_del(const void *request, struct api_ctx *) {
	const struct gr_acl_filter_del_req *req = request;
	struct acl_filter *filter = NULL;
	struct acl_set *set = NULL;

	rte_hash_lookup_data(acl_filters, &req->filter_id, (void **)&filter);
	if (filter == NULL) {
		if (req->missing_ok)
			return api_out(0, 0, NULL);
		return api_out(ENOENT, 0, NULL);
	}

	rte_hash_lookup_data(acl_sets, &filter->set_id, (void **)&set);
	if (set != NULL)
		set->n_filters--;

	rte_hash_del_key(acl_filters, &req->filter_id);
	event_push(GR_EVENT_ACL_FILTER_DEL, filter);

	// Recompile first: the new generation drops the rules referencing
	// the filter stats, which are freed once the workers are done.
	acl_recompile();
	free(filter->stats);
	free(filter);
	return api_out(0, 0, NULL);
}

static struct api_out acl_filter_list(const void *request, struct api_ctx *ctx) {
	const struct gr_acl_filter_list_req *req = request;
	struct acl_filter *filter = NULL;
	uint32_t next = 0;
	const void *key;

	while (rte_hash_iterate(acl_filters, &key, (void **)&filter, &next) >= 0) {
		size_t len = sizeof(filter->base) + filter->n_ifaces * sizeof(uint16_t);
		struct gr_acl_filter *record;

		if (req->vrf_id != GR_VRF_ID_UNDEF && filter->vrf_id != req->vrf_id)
			continue;

		record = malloc(len);
		if (record == NULL)
			return api_out(ENOMEM, 0, NULL);
		memcpy(record, &filter->base, len);
		record->pkts = atomic_load_explicit(&filter->stats->pkts, memory_order_relaxed);
		api_send(ctx, len, record);
		free(record);
	}

	return api_out(0, 0, NULL);
}

// ---------------------------------------------------------------------------
// module

// A new interface may be referenced by existing filters: recompile so
// that the rules of the filters referencing its id become effective.
// Events are delivered on the control plane thread, the same thread that
// runs acl_recompile, so there is no concurrency to worry about.
static void acl_iface_event_cb(uint32_t, const void *) {
	acl_recompile();
}

static void acl_init(struct event_base *) {
	acl_sets = acl_hash_new("acl-sets", sizeof(uint32_t), gr_config.max_acl_sets);
	acl_entries = acl_hash_new(
		"acl-entries", sizeof(struct acl_entry_key), gr_config.max_acl_entries
	);
	acl_filters = acl_hash_new("acl-filters", sizeof(uint32_t), gr_config.max_acl_filters);
	if (acl_sets == NULL || acl_entries == NULL || acl_filters == NULL)
		ABORT("cannot allocate the ACL hashes");
}

static void acl_fini(struct event_base *) {
	vec struct acl_filter **filters = NULL;
	struct acl_filter *filter = NULL;
	struct acl_entry *entry = NULL;
	struct acl_set *set = NULL;
	uint32_t next = 0;
	const void *key;

	// Remove the filters from the hash before the last recompile so
	// that it publishes an empty generation: the classes of the
	// previous generation reference the filter stats and can only be
	// freed once the dataplane workers are done with them (the RCU
	// grace period inside acl_recompile). Free the objects afterwards.
	while (rte_hash_iterate(acl_filters, &key, (void **)&filter, &next) >= 0)
		vec_add(filters, filter);
	vec_foreach (filter, filters)
		rte_hash_del_key(acl_filters, &filter->base.filter_id);

	acl_recompile(); // publish an empty generation

	vec_foreach (filter, filters) {
		free(filter->stats);
		free(filter);
	}
	vec_free(filters);

	next = 0;
	while (rte_hash_iterate(acl_entries, &key, (void **)&entry, &next) >= 0)
		free(entry);
	next = 0;
	while (rte_hash_iterate(acl_sets, &key, (void **)&set, &next) >= 0)
		free(set);

	rte_hash_free(acl_filters);
	rte_hash_free(acl_entries);
	rte_hash_free(acl_sets);
	acl_filters = NULL;
	acl_entries = NULL;
	acl_sets = NULL;
}

static struct module module = {
	.name = "acl",
	.depends_on = "iface",
	.init = acl_init,
	.fini = acl_fini,
};

// The filter objects are variable length: serialize the interface list
// following the base structure.
static int acl_filter_serialize(const void *obj, void **buf) {
	const struct acl_filter *filter = obj;
	size_t len = sizeof(filter->base) + filter->n_ifaces * sizeof(uint16_t);

	*buf = malloc(len);
	if (*buf == NULL)
		return -1;
	memcpy(*buf, &filter->base, len);
	return len;
}

RTE_INIT(acl_module_init) {
	api_handler(GR_ACL_SET_ADD, acl_set_add);
	api_handler(GR_ACL_SET_DEL, acl_set_del);
	api_handler(GR_ACL_SET_LIST, acl_set_list);
	api_handler(GR_ACL_ENTRY_ADD, acl_entry_add);
	api_handler(GR_ACL_ENTRY_DEL, acl_entry_del);
	api_handler(GR_ACL_ENTRY_LIST, acl_entry_list);
	api_handler(GR_ACL_FILTER_ADD, acl_filter_add);
	api_handler(GR_ACL_FILTER_DEL, acl_filter_del);
	api_handler(GR_ACL_FILTER_LIST, acl_filter_list);
	event_serializer(GR_EVENT_ACL_SET_ADD, NULL);
	event_serializer(GR_EVENT_ACL_SET_DEL, NULL);
	event_serializer(GR_EVENT_ACL_ENTRY_ADD, NULL);
	event_serializer(GR_EVENT_ACL_ENTRY_DEL, NULL);
	event_serializer(GR_EVENT_ACL_FILTER_ADD, acl_filter_serialize);
	event_serializer(GR_EVENT_ACL_FILTER_DEL, acl_filter_serialize);
	event_subscribe(GR_EVENT_IFACE_POST_ADD, acl_iface_event_cb);
	module_register(&module);
}
