// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#pragma once

#include <gr_acl.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

// Control plane objects. Only manipulated from the main thread. The
// dataplane only reaches them through the classification contexts hung
// off struct iface and through the per filter hit counters.

struct acl_set {
	BASE(gr_acl_set);
	struct acl_entry *entries; // entries of this set, insertion order
	uint32_t n_entries;
	uint32_t n_filters;
};

struct acl_entry {
	BASE(gr_acl_set_entry);
	struct acl_entry *next; // next entry of the same set
};

// Separately allocated so that its address is stable across filter
// updates: the classification results reference it and the filter object
// itself is reallocated when its interface list changes.
struct acl_filter_stats {
	_Atomic uint64_t pkts; // number of packets matched by this filter
};

struct acl_filter {
	uint32_t seq; // insertion order, used as the classification priority
	struct acl_filter_stats *stats;
	BASE(gr_acl_filter); // iface_ids[] follow this struct (last member)
};

// Classification context, one per (address family, interface with rules).
// Referenced by the matching iface through an RCU protected pointer: the
// control plane swaps the pointers, waits for a grace period and then
// frees the previous generation.
struct acl_class {
	struct rte_acl_ctx *acl;
	struct acl_result *results; // shared by the generation, rule userdata indexed
	bool l4; // rules use layer 4 fields → parse before classifying
};

// What a winning rule resolves to. The index is stored as the rule
// userdata; index 0 is reserved (no match).
struct acl_result {
	struct acl_filter_stats *stats;
};

// Classification key layout, shared by the datapath key builder and the
// control plane rule compiler. All multi byte key fields are stored in
// big endian wire order so that the key can be filled without any byte
// swap; the rule field values are plain host order numbers.
//
// rte_acl consumes the key with a fixed pattern (GET_NEXT_4BYTES in
// lib/acl/acl_run.h): one byte for the first input group, then exactly
// four consecutive bytes for every additional input group, starting at
// the key offset of the group's first field. The layouts must follow
// these rules, otherwise the fields are silently compared against the
// wrong key bytes:
//
//   - input group 0 holds exactly one byte,
//   - every other input group holds fields totaling exactly four bytes,
//     contiguous in the key from the offset of the group's first field.
//
// Whole input groups whose fields are wild for every rule of a context
// are dropped by rte_acl at build time, which preserves the alignment
// of the groups that remain. The ACL4_F_*/ACL6_F_* enums give the field
// indices (and, by array position, the def order) and the
// ACL4_OFF_*/ACL6_OFF_* macros give the key offsets: the control plane
// field definitions and the datapath key builders must agree on both.
//
// IPv4 key (24 bytes):
//
//   group 0: proto@0
//   group 1: dscp@1, frag_flags@2, frag_offset@3
//   group 2: src@8
//   group 3: dst@12
//   group 4: sport@16, dport@18
//   group 5: tcp_flags@20, pkt_len@21, pad@23
//
// IPv6 key (48 bytes):
//
//   group 0: proto@0
//   group 1: dscp@1, tcp_flags@2, pkt_len@3
//   group 2: flow_label@5
//   group 3-6: src@9,13,17,21
//   group 7-10: dst@25,29,33,37
//   group 11: sport@41, dport@43
#define ACL_KEY4_LEN 24
#define ACL_KEY6_LEN 48

enum {
	ACL4_F_PROTO = 0,
	ACL4_F_DSCP,
	ACL4_F_FRAG_FLAGS,
	ACL4_F_FRAG_OFFSET,
	ACL4_F_SRC,
	ACL4_F_DST,
	ACL4_F_L4_A,
	ACL4_F_L4_B,
	ACL4_F_TCP_FLAGS,
	ACL4_F_PKT_LEN,
	ACL4_F_PAD, // always wild, keeps input group 5 four bytes long
	ACL4_F_COUNT,
};

enum {
	ACL6_F_PROTO = 0,
	ACL6_F_DSCP,
	ACL6_F_TCP_FLAGS,
	ACL6_F_PKT_LEN,
	ACL6_F_FLOW_LABEL,
	ACL6_F_SRC = 5, // + 3 more u32 address chunks
	ACL6_F_DST = 9, // + 3 more u32 address chunks
	ACL6_F_L4_A = 13,
	ACL6_F_L4_B,
	ACL6_F_COUNT,
};

// IPv4 key offsets.
#define ACL4_OFF_PROTO 0
#define ACL4_OFF_DSCP 1
#define ACL4_OFF_FRAG_FLAGS 2
#define ACL4_OFF_FRAG_OFFSET 3
#define ACL4_OFF_SRC 8
#define ACL4_OFF_DST 12
#define ACL4_OFF_SPORT 16
#define ACL4_OFF_DPORT 18
#define ACL4_OFF_TCP_FLAGS 20
#define ACL4_OFF_PKT_LEN 21
#define ACL4_OFF_PAD 23

// IPv6 key offsets.
#define ACL6_OFF_PROTO 0
#define ACL6_OFF_DSCP 1
#define ACL6_OFF_TCP_FLAGS 2
#define ACL6_OFF_PKT_LEN 3
#define ACL6_OFF_FLOW_LABEL 5
#define ACL6_OFF_SRC 9
#define ACL6_OFF_DST 25
#define ACL6_OFF_SPORT 41
#define ACL6_OFF_DPORT 43

// Fragment flag bits in the key frag_flags byte.
#define ACL_FRAG_DONT 0x1 // DF bit set
#define ACL_FRAG_MORE 0x2 // MF bit set

// FRR FRAGMENT_* criteria (bgpd/bgp_pbr.h), carried in the filter.
#define GR_ACL_FRAGMENT_DONT 0x1
#define GR_ACL_FRAGMENT_IS 0x2
#define GR_ACL_FRAGMENT_FIRST 0x4
#define GR_ACL_FRAGMENT_LAST 0x8

// Check an ingress packet against the classification context of its
// interface. Returns true when the packet must be dropped.
//
// TODO: support the GR_ACL_ACTION_MARK action (set the firewall mark in
// the packet metadata and forward instead of dropping); requires policy
// routing rules to consume the mark.
bool gr_acl_input_drop4(
	const struct acl_class *acl,
	const struct rte_mbuf *m,
	const struct rte_ipv4_hdr *ip
);
bool gr_acl_input_drop6(
	const struct acl_class *acl,
	const struct rte_mbuf *m,
	const struct rte_ipv6_hdr *ip
);
