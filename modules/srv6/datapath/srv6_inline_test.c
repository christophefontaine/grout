// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include <cmocka.h>
#include <rte_mbuf.h>
#include <rte_ip6.h>

#include <gr_srv6_nexthop.h>

// Define constants that would normally come from other headers
#define RTE_PKTMBUF_HEADROOM 128
#define RTE_PTYPE_L3_IPV6 0x00000040
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef RTE_IPV6_SRCRT_TYPE_4
#define RTE_IPV6_SRCRT_TYPE_4 4
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

// Define edge types that would normally come from srv6_output.c
typedef enum {
	IP6_OUTPUT,
	NO_HEADROOM,
	INVALID,
	NO_ROUTE,
} rte_edge_t;

// Mock structures for testing
struct fake_mbuf {
	struct rte_mbuf mbuf;
	uint8_t data[2048];
	size_t data_len;
};

static void fm_init_ipv6(
	struct fake_mbuf *fm,
	const struct rte_ipv6_addr *src,
	const struct rte_ipv6_addr *dst,
	uint8_t next_hdr,
	uint16_t payload_len
) {
	struct rte_ipv6_hdr *ip6;

	memset(fm, 0, sizeof(*fm));
	fm->mbuf.buf_addr = fm->data;
	fm->mbuf.data_off = RTE_PKTMBUF_HEADROOM;
	fm->mbuf.pkt_len = sizeof(*ip6) + payload_len;
	fm->mbuf.data_len = fm->mbuf.pkt_len;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV6;

	ip6 = (struct rte_ipv6_hdr *)(fm->data + fm->mbuf.data_off);
	ip6->vtc_flow = rte_cpu_to_be_32(0x60000000); // IPv6 version
	ip6->payload_len = rte_cpu_to_be_16(payload_len);
	ip6->proto = next_hdr;
	ip6->hop_limits = 64;
	ip6->src_addr = *src;
	ip6->dst_addr = *dst;
}

// Copy of srv6_inline_insert function for testing
// RFC 8754 inline mode: insert SRH directly into IPv6 packet
static rte_edge_t srv6_inline_insert(struct rte_mbuf *m, const struct nexthop_info_srv6_output *d) {
	struct rte_ipv6_hdr *ip6;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_addr *segments;
	uint32_t srh_len;
	uint16_t payload_len;
	uint8_t original_next_hdr;
	uint16_t k;

	ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);

	// Calculate SRH length
	srh_len = sizeof(*srh) + (d->n_seglist * sizeof(d->seglist[0]));

	// Prepend space for SRH
	srh = (struct rte_ipv6_routing_ext *)rte_pktmbuf_prepend(m, srh_len);
	if (unlikely(srh == NULL)) {
		return NO_HEADROOM;
	}

	// Move IPv6 header to new position
	ip6 = (struct rte_ipv6_hdr *)srh;
	memmove(ip6, (uint8_t *)srh + srh_len, sizeof(*ip6));

	// Save original next header and update IPv6 header
	original_next_hdr = ip6->proto;
	ip6->proto = IPPROTO_ROUTING;
	payload_len = rte_be_to_cpu_16(ip6->payload_len) + srh_len;
	ip6->payload_len = rte_cpu_to_be_16(payload_len);

	// Setup SRH after IPv6 header
	srh = (struct rte_ipv6_routing_ext *)(ip6 + 1);
	srh->next_hdr = original_next_hdr;
	srh->hdr_len = (srh_len / 8) - 1;
	srh->type = RTE_IPV6_SRCRT_TYPE_4;
	srh->segments_left = d->n_seglist - 1;
	srh->last_entry = d->n_seglist - 1;
	srh->flag = 0;
	srh->tag = 0;

	// Copy segments in reverse order (per RFC 8754)
	segments = (struct rte_ipv6_addr *)(srh + 1);
	for (k = 0; k < d->n_seglist; k++)
		segments[d->n_seglist - k - 1] = d->seglist[k];

	// Set destination to first segment
	ip6->dst_addr = d->seglist[0];

	return IP6_OUTPUT;
}

static void test_srv6_inline_basic_single_segment(void **state) {
	(void)state;
	struct fake_mbuf fm;
	struct nexthop_info_srv6_output nh_info;
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr seg1 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}};
	struct rte_ipv6_hdr *ip6;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_addr *segments;
	rte_edge_t result;

	// Initialize fake mbuf with IPv6 packet
	fm_init_ipv6(&fm, &src, &dst, IPPROTO_TCP, 20);

	// Setup nexthop info with single segment
	nh_info.encap = SR_H_INLINE;
	nh_info.n_seglist = 1;
	nh_info.seglist = &seg1;

	// Call function under test
	result = srv6_inline_insert(&fm.mbuf, &nh_info);

	// Verify return value
	assert_int_equal(result, IP6_OUTPUT);

	// Verify IPv6 header was moved and updated
	ip6 = rte_pktmbuf_mtod(&fm.mbuf, struct rte_ipv6_hdr *);
	assert_int_equal(ip6->proto, IPPROTO_ROUTING);
	assert_int_equal(rte_be_to_cpu_16(ip6->payload_len), 20 + sizeof(*srh) + sizeof(seg1));

	// Verify destination was set to first segment
	assert_memory_equal(&ip6->dst_addr, &seg1, sizeof(seg1));

	// Verify SRH was inserted correctly
	srh = (struct rte_ipv6_routing_ext *)(ip6 + 1);
	assert_int_equal(srh->next_hdr, IPPROTO_TCP);
	assert_int_equal(srh->type, RTE_IPV6_SRCRT_TYPE_4);
	assert_int_equal(srh->segments_left, 0); // n_seglist - 1
	assert_int_equal(srh->last_entry, 0); // n_seglist - 1
	assert_int_equal(srh->flag, 0);
	assert_int_equal(srh->tag, 0);

	// Verify segment was copied correctly
	segments = (struct rte_ipv6_addr *)(srh + 1);
	assert_memory_equal(&segments[0], &seg1, sizeof(seg1));
}

static void test_srv6_inline_multiple_segments(void **state) {
	(void)state;
	struct fake_mbuf fm;
	struct nexthop_info_srv6_output nh_info;
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr segments_list[3] = {
		{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}},
		{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0}},
		{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0}}
	};
	struct rte_ipv6_hdr *ip6;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_addr *segments;
	rte_edge_t result;

	// Initialize fake mbuf with IPv6 packet
	fm_init_ipv6(&fm, &src, &dst, IPPROTO_UDP, 8);

	// Setup nexthop info with multiple segments
	nh_info.encap = SR_H_INLINE;
	nh_info.n_seglist = 3;
	nh_info.seglist = segments_list;

	// Call function under test
	result = srv6_inline_insert(&fm.mbuf, &nh_info);

	// Verify return value
	assert_int_equal(result, IP6_OUTPUT);

	// Verify IPv6 header
	ip6 = rte_pktmbuf_mtod(&fm.mbuf, struct rte_ipv6_hdr *);
	assert_int_equal(ip6->proto, IPPROTO_ROUTING);

	// Verify destination was set to first segment
	assert_memory_equal(&ip6->dst_addr, &segments_list[0], sizeof(segments_list[0]));

	// Verify SRH
	srh = (struct rte_ipv6_routing_ext *)(ip6 + 1);
	assert_int_equal(srh->next_hdr, IPPROTO_UDP);
	assert_int_equal(srh->type, RTE_IPV6_SRCRT_TYPE_4);
	assert_int_equal(srh->segments_left, 2); // n_seglist - 1
	assert_int_equal(srh->last_entry, 2); // n_seglist - 1

	// Verify segments are in reverse order (per RFC 8754)
	segments = (struct rte_ipv6_addr *)(srh + 1);
	assert_memory_equal(&segments[0], &segments_list[2], sizeof(segments_list[2])); // seg3
	assert_memory_equal(&segments[1], &segments_list[1], sizeof(segments_list[1])); // seg2
	assert_memory_equal(&segments[2], &segments_list[0], sizeof(segments_list[0])); // seg1
}

static void test_srv6_inline_no_headroom(void **state) {
	(void)state;
	struct fake_mbuf fm;
	struct nexthop_info_srv6_output nh_info;
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr seg1 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}};
	rte_edge_t result;

	// Initialize fake mbuf with no headroom
	fm_init_ipv6(&fm, &src, &dst, IPPROTO_TCP, 20);
	fm.mbuf.data_off = 0; // No headroom available

	// Setup nexthop info
	nh_info.encap = SR_H_INLINE;
	nh_info.n_seglist = 1;
	nh_info.seglist = &seg1;

	// Call function under test - should fail due to no headroom
	result = srv6_inline_insert(&fm.mbuf, &nh_info);

	// Verify error return
	assert_int_equal(result, NO_HEADROOM);
}

static void test_srv6_inline_header_preservation(void **state) {
	(void)state;
	struct fake_mbuf fm;
	struct nexthop_info_srv6_output nh_info;
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr seg1 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}};
	struct rte_ipv6_hdr *ip6_orig, *ip6_new;
	struct rte_ipv6_routing_ext *srh;
	uint32_t original_flow_label = 0x12345;
	uint8_t original_hop_limit = 42;
	rte_edge_t result;

	// Initialize fake mbuf with specific IPv6 header values
	fm_init_ipv6(&fm, &src, &dst, IPPROTO_ICMPV6, 64);
	ip6_orig = rte_pktmbuf_mtod(&fm.mbuf, struct rte_ipv6_hdr *);
	ip6_orig->vtc_flow = rte_cpu_to_be_32(0x60000000 | original_flow_label);
	ip6_orig->hop_limits = original_hop_limit;

	// Setup nexthop info
	nh_info.encap = SR_H_INLINE;
	nh_info.n_seglist = 1;
	nh_info.seglist = &seg1;

	// Call function under test
	result = srv6_inline_insert(&fm.mbuf, &nh_info);

	// Verify return value
	assert_int_equal(result, IP6_OUTPUT);

	// Verify IPv6 header fields were preserved
	ip6_new = rte_pktmbuf_mtod(&fm.mbuf, struct rte_ipv6_hdr *);
	assert_memory_equal(&ip6_new->src_addr, &src, sizeof(src));
	assert_int_equal(rte_be_to_cpu_32(ip6_new->vtc_flow) & 0xfffff, original_flow_label);
	assert_int_equal(ip6_new->hop_limits, original_hop_limit);

	// Verify SRH next_hdr points to original protocol
	srh = (struct rte_ipv6_routing_ext *)(ip6_new + 1);
	assert_int_equal(srh->next_hdr, IPPROTO_ICMPV6);
}

// Test runner
int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_srv6_inline_basic_single_segment),
		cmocka_unit_test(test_srv6_inline_multiple_segments),
		cmocka_unit_test(test_srv6_inline_no_headroom),
		cmocka_unit_test(test_srv6_inline_header_preservation),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
