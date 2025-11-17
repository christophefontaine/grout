// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_fib6.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_srv6.h>
#include <gr_srv6_nexthop.h>
#include <gr_trace.h>
#include <gr_vec.h>

#include <rte_ip6.h>

//
// srv6 source node. encapsulate traffic
//

enum {
	IP6_OUTPUT = 0,
	INVALID,
	NO_ROUTE,
	NO_HEADROOM,
	EDGE_COUNT,
};

struct trace_srv6_data {
	union {
		struct ip4_net dest4;
		struct ip6_net dest6;
	};
	bool is_dest6;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	if (t->is_dest6)
		return snprintf(buf, len, "match=" IP6_F "/%hhu", &t->dest6.ip, t->dest6.prefixlen);
	else
		return snprintf(buf, len, "match=" IP4_F "/%hhu", &t->dest4.ip, t->dest4.prefixlen);
}

// RFC 8754 inline mode: insert SRH directly into IPv6 packet
static rte_edge_t srv6_inline_insert(struct rte_mbuf *m, const struct nexthop_info_srv6_output *d) {
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_addr *segments;
	uint8_t original_next_hdr;
	struct rte_ipv6_hdr *ip6;
	uint16_t payload_len;
	uint32_t srh_len;
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

	// Set last segment to destination
	segments[srh->segments_left] = ip6->dst_addr;
	// Set destination to first segment
	ip6->dst_addr = d->seglist[0];

	return IP6_OUTPUT;
}

// called from 'ip6_output' or 'ip_output' node
static uint16_t
srv6_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct nexthop_info_srv6_output *d;
	const struct nexthop_info_l3 *l3;
	struct trace_srv6_data *t = NULL;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_hdr *outer_ip6;
	const struct nexthop *nh;
	uint32_t hdrlen, plen;
	uint8_t proto, reduc;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		if (gr_mbuf_is_traced(m))
			t = gr_mbuf_trace_add(m, node, sizeof(*t));

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			struct rte_ipv4_hdr *inner_ip4;

			nh = ip_output_mbuf_data(m)->nh;
			d = nexthop_info_srv6_output(nh);
			if (d == NULL) {
				edge = INVALID;
				goto next;
			}

			// Inline mode not applicable to IPv4 packets
			if (d->encap == SR_H_INLINE) {
				edge = INVALID;
				goto next;
			}
			if (t != NULL && nh->type == GR_NH_T_L3) {
				l3 = nexthop_info_l3(nh);
				t->dest4.ip = l3->ipv4;
				t->dest4.prefixlen = l3->prefixlen;
				t->is_dest6 = false;
			}
			inner_ip4 = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			plen = rte_be_to_cpu_16(inner_ip4->total_length);
			proto = IPPROTO_IPIP;

		} else if (m->packet_type & RTE_PTYPE_L3_IPV6) {
			struct rte_ipv6_hdr *inner_ip6;

			nh = ip6_output_mbuf_data(m)->nh;
			d = nexthop_info_srv6_output(nh);
			if (d == NULL) {
				edge = INVALID;
				goto next;
			}

			if (t != NULL && nh->type == GR_NH_T_L3) {
				l3 = nexthop_info_l3(nh);
				t->dest6.ip = l3->ipv6;
				t->dest6.prefixlen = l3->prefixlen;
				t->is_dest6 = true;
			}

			// Handle inline mode for IPv6 packets
			if (d->encap == SR_H_INLINE) {
				edge = srv6_inline_insert(m, d);
				if (edge != IP6_OUTPUT)
					goto next;

				// Update nexthop for forwarding
				nh = fib6_lookup(nh->vrf_id, GR_IFACE_ID_UNDEF, d->seglist);
				if (nh == NULL) {
					edge = NO_ROUTE;
					goto next;
				}
				ip6_output_mbuf_data(m)->nh = nh;
				goto next;
			}

			inner_ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			plen = rte_be_to_cpu_16(inner_ip6->payload_len);
			proto = IPPROTO_IPV6;

		} else {
			edge = INVALID;
			goto next;
		}

		// Encapsulate with another IPv6 header
		hdrlen = sizeof(*outer_ip6);
		reduc = d->encap == SR_H_ENCAPS_RED ? 1 : 0;
		if (d->n_seglist > reduc)
			hdrlen += sizeof(*srh) + (d->n_seglist * sizeof(d->seglist[0]));

		outer_ip6 = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, hdrlen);
		if (unlikely(outer_ip6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		if (d->n_seglist > reduc) {
			struct rte_ipv6_addr *segments;
			uint16_t k;

			srh = (struct rte_ipv6_routing_ext *)(outer_ip6 + 1);
			srh->next_hdr = proto;
			srh->hdr_len = (hdrlen - sizeof(*outer_ip6)) / 8 - 1;
			srh->type = RTE_IPV6_SRCRT_TYPE_4;
			srh->segments_left = d->n_seglist - 1;
			srh->last_entry = d->n_seglist - 1;
			srh->flags = 0;
			srh->tag = 0;

			segments = (struct rte_ipv6_addr *)(srh + 1);
			for (k = reduc; k < d->n_seglist; k++)
				segments[d->n_seglist - k - 1] = d->seglist[k];
			proto = IPPROTO_ROUTING;
			plen += hdrlen - sizeof(*outer_ip6);
		}

		// Resolve nexthop for the encapsulated packet.
		nh = fib6_lookup(nh->vrf_id, GR_IFACE_ID_UNDEF, d->seglist);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		ip6_output_mbuf_data(m)->nh = nh;

		nh = sr_tunsrc_get(nh->iface_id, &d->seglist[0]);
		if (nh == NULL) {
			// cannot output packet on interface that does not have ip6 addr
			edge = NO_ROUTE;
			goto next;
		}
		l3 = nexthop_info_l3(nh);

		ip6_set_fields(outer_ip6, plen, proto, &l3->ipv6, &d->seglist[0]);
		edge = IP6_OUTPUT;

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_output_register(void) {
	ip_output_register_nexthop_type(GR_NH_T_SR6_OUTPUT, "sr6_output");
	ip6_output_register_nexthop_type(GR_NH_T_SR6_OUTPUT, "sr6_output");
}

static struct rte_node_register srv6_output_node = {
	.name = "sr6_output",

	.process = srv6_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP6_OUTPUT] = "ip6_output",
		[INVALID] = "sr6_pkt_invalid",
		[NO_ROUTE] = "sr6_source_no_route",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info srv6_output_info = {
	.node = &srv6_output_node,
	.type = GR_NODE_T_L3,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_output_register,
};

GR_NODE_REGISTER(srv6_output_info);

GR_DROP_REGISTER(sr6_pkt_invalid);
GR_DROP_REGISTER(sr6_source_no_route);

#ifdef __GROUT_UNIT_TEST__
#include <gr_cmocka.h>

// Mock structures for testing
struct fake_mbuf {
	struct rte_mbuf mbuf;
	uint8_t data[2048];
	size_t data_len;
};

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
struct nexthop *tunsrc_nh = NULL;

mock_func(struct nexthop *, addr6_get_preferred(uint16_t, const void *));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(const struct nexthop *, fib6_lookup(uint16_t, uint16_t, const struct rte_ipv6_addr *));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(void, ip_output_register_nexthop_type(gr_nh_type_t, const char *));
mock_func(void, ip6_output_register_nexthop_type(gr_nh_type_t, const char *));

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

static void test_srv6_inline_basic_single_segment(void **state) {
	(void)state;
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr seg1 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}};
	struct nexthop_info_srv6_output nh_info;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_addr *segments;
	struct rte_ipv6_hdr *ip6;
	struct fake_mbuf fm;
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

static void test_srv6_inline_multiple_segments(void ** /* state */) {
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr segments_list[3] = {
		{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}},
		{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0}},
		{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0}}
	};
	struct nexthop_info_srv6_output nh_info;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_addr *segments;
	struct rte_ipv6_hdr *ip6;
	struct fake_mbuf fm;
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

static void test_srv6_inline_no_headroom(void ** /* state */) {
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr seg1 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}};
	struct nexthop_info_srv6_output nh_info;
	struct fake_mbuf fm;
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

static void test_srv6_inline_header_preservation(void ** /* state */) {
	struct rte_ipv6_addr src = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
	struct rte_ipv6_addr dst = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};
	struct rte_ipv6_addr seg1 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}};
	struct rte_ipv6_hdr *ip6_orig, *ip6_new;
	struct nexthop_info_srv6_output nh_info;
	uint32_t original_flow_label = 0x12345;
	struct rte_ipv6_routing_ext *srh;
	uint8_t original_hop_limit = 42;
	struct fake_mbuf fm;
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
#endif
