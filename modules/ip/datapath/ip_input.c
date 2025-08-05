// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_fib4.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

enum edges {
	FORWARD = 0,
	OUTPUT,
	LOCAL,
	NO_ROUTE,
	BAD_CHECKSUM,
	BAD_LENGTH,
	BAD_VERSION,
	OTHER_HOST,
	EDGE_COUNT,
};

static rte_edge_t nh_type_edges[256] = {FORWARD};

void ip_input_register_nexthop_type(gr_nh_type_t type, const char *next_node) {
	LOG(DEBUG, "ip_input: nexthop type=%u -> %s", type, next_node);
	if (type == 0)
		ABORT("invalid nexthop type=%u", type);
	if (nh_type_edges[type] != FORWARD)
		ABORT("next node already registered for nexthop type=%u", type);
	nh_type_edges[type] = gr_node_attach_parent("ip_input", next_node);
}

static inline rte_edge_t ip_validate_mbuf(struct rte_mbuf *mbuf, struct rte_ipv4_hdr *ip) {
	// RFC 1812 section 5.2.2 IP Header Validation
	//
	// (1) The packet length reported by the Link Layer must be large
	//     enough to hold the minimum length legal IP datagram (20 bytes).
	if (rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_ipv4_hdr)) {
		// XXX: call rte_pktmuf_data_len is used to ensure that the IPv4 header
		// is located on the first segment. IPv4 headers located on the second,
		// third or subsequent segments, as well spanning segment boundaries, are
		// not currently handled.
		return BAD_LENGTH;
	}
	// (2) The IP checksum must be correct.
	switch (mbuf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) {
	case RTE_MBUF_F_RX_IP_CKSUM_NONE:
	case RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN:
		// if this is not checked in H/W, check it.
		if (rte_ipv4_cksum(ip)) {
			return BAD_CHECKSUM;
		}
		break;
	case RTE_MBUF_F_RX_IP_CKSUM_BAD:
		return BAD_CHECKSUM;
	}

	// (3) The IP version number must be 4.  If the version number is not 4
	//     then the packet may be another version of IP, such as IPng or
	//     ST-II.
	if (ip->version != IPVERSION) {
		return BAD_VERSION;
	}

	// (4) The IP header length field must be large enough to hold the
	//     minimum length legal IP datagram (20 bytes = 5 words).
	if (rte_ipv4_hdr_len(ip) < sizeof(struct rte_ipv4_hdr)) {
		return BAD_LENGTH;
	}

	// (5) The IP total length field must be large enough to hold the IP
	//     datagram header, whose length is specified in the IP header
	//     length field.
	if (rte_cpu_to_be_16(ip->total_length) < sizeof(struct rte_ipv4_hdr)) {
		return BAD_LENGTH;
	}
	return 0;
}

static inline rte_edge_t edge_for_nh(const struct nexthop *nh, ip4_addr_t dst, int domain) {
	if (unlikely(nh == NULL))
		return NO_ROUTE;
	else if (nh->flags & GR_NH_F_LOCAL && dst == nh->ipv4)
		return LOCAL;
	else if (domain == ETH_DOMAIN_LOOPBACK)
		return OUTPUT;
	else
		return FORWARD;
}

static uint16_t
ip_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_input_mbuf_data *e;
	struct ip_output_mbuf_data *d;
	const struct iface *iface;
	const struct nexthop *nh;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t i = 0;

	__m128i is_valid = _mm_setzero_si128();
	__m128i loopback = _mm_set1_epi32(ETH_DOMAIN_LOOPBACK);
	__m128i local = _mm_set1_epi32(ETH_DOMAIN_LOCAL);
	//__m128i broadcast = _mm_set1_epi32(ETH_DOMAIN_BROADCAST);
	//__m128i multicast = _mm_set1_epi32(ETH_DOMAIN_MULTICAST);

	while (i + 4 < nb_objs) {
		if (i + 8 < nb_objs) {
			rte_prefetch0(objs[i + 4]);
			rte_prefetch0(objs[i + 5]);
			rte_prefetch0(objs[i + 6]);
			rte_prefetch0(objs[i + 7]);
		}
		struct rte_mbuf *m0 = objs[i + 0];
		struct rte_mbuf *m1 = objs[i + 1];
		struct rte_mbuf *m2 = objs[i + 2];
		struct rte_mbuf *m3 = objs[i + 3];
		struct rte_ipv4_hdr *ip0 = rte_pktmbuf_mtod(m0, struct rte_ipv4_hdr *);
		struct rte_ipv4_hdr *ip1 = rte_pktmbuf_mtod(m1, struct rte_ipv4_hdr *);
		struct rte_ipv4_hdr *ip2 = rte_pktmbuf_mtod(m2, struct rte_ipv4_hdr *);
		struct rte_ipv4_hdr *ip3 = rte_pktmbuf_mtod(m3, struct rte_ipv4_hdr *);

		rte_edge_t v0 = ip_validate_mbuf(m0, ip0);
		rte_edge_t v1 = ip_validate_mbuf(m1, ip1);
		rte_edge_t v2 = ip_validate_mbuf(m2, ip2);
		rte_edge_t v3 = ip_validate_mbuf(m3, ip3);
		struct eth_input_mbuf_data *e0 = eth_input_mbuf_data(m0);
		struct eth_input_mbuf_data *e1 = eth_input_mbuf_data(m1);
		struct eth_input_mbuf_data *e2 = eth_input_mbuf_data(m2);
		struct eth_input_mbuf_data *e3 = eth_input_mbuf_data(m3);
		const struct iface *i0 = e0->iface;
		const struct iface *i1 = e1->iface;
		const struct iface *i2 = e2->iface;
		const struct iface *i3 = e3->iface;

		auto d0 = e0->domain;
		auto d1 = e1->domain;
		auto d2 = e2->domain;
		auto d3 = e3->domain;

		__m128i v = _mm_set_epi32(v0, v1, v2, v3);
		__m128i d = _mm_set_epi32(d0, d1, d2, d3);
		__m128i mbuf_valid = _mm_cmpeq_epi32(v, is_valid);
		__m128i domains = _mm_cmpeq_epi32(d, loopback) | _mm_cmpeq_epi16(d, local);

		int16_t res = _mm_movemask_epi8(mbuf_valid);
		if (res != -1) {
			break; // mbuf invalid, process all vector 1 element at a time
		}

		res = _mm_movemask_epi8(domains);
		if (res != -1) {
			break;
		}
		const struct nexthop *nhs[4] = {0};
		
		if (i0->vrf_id == i1->vrf_id && i1->vrf_id == i3->vrf_id
		    && i2->vrf_id == i3->vrf_id) {
			fib4_lookup_x4(
				i0->vrf_id,
				ip0->dst_addr,
				ip1->dst_addr,
				ip2->dst_addr,
				ip3->dst_addr,
				nhs
			);
		} else  {
			nhs[0] = fib4_lookup(i0->vrf_id, ip0->dst_addr);
			nhs[1] = fib4_lookup(i1->vrf_id, ip1->dst_addr);
			nhs[2] = fib4_lookup(i2->vrf_id, ip2->dst_addr);
			nhs[3] = fib4_lookup(i3->vrf_id, ip3->dst_addr);
		}

		v0 = edge_for_nh(nhs[0], ip0->dst_addr, e0->domain);
		v1 = edge_for_nh(nhs[1], ip1->dst_addr, e1->domain);
		v2 = edge_for_nh(nhs[2], ip2->dst_addr, e2->domain);
		v3 = edge_for_nh(nhs[3], ip3->dst_addr, e3->domain);

		if (gr_mbuf_is_traced(m0)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(m0, node, sizeof(*t));
			*t = *ip0;
		}
		if (gr_mbuf_is_traced(m1)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(m1, node, sizeof(*t));
			*t = *ip1;
		}
		if (gr_mbuf_is_traced(m2)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(m2, node, sizeof(*t));
			*t = *ip2;
		}

		if (gr_mbuf_is_traced(m3)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(m3, node, sizeof(*t));
			*t = *ip3;
		}

		 ip_output_mbuf_data(m0)->nh = nhs[0];
		 ip_output_mbuf_data(m1)->nh = nhs[1];
		 ip_output_mbuf_data(m2)->nh = nhs[2];
		 ip_output_mbuf_data(m3)->nh = nhs[3];

		if (v0 == v1 && v1 == v2 && v2 == v3)
			rte_node_enqueue_x4(graph, node, v0, m0, m1, m2, m3);
		else {
			rte_node_enqueue_x1(graph, node, v0, m0);
			rte_node_enqueue_x1(graph, node, v1, m1);
			rte_node_enqueue_x1(graph, node, v2, m2);
			rte_node_enqueue_x1(graph, node, v3, m3);
		}

		i += 4;
	}

	for (; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		e = eth_input_mbuf_data(mbuf);
		iface = e->iface;
		nh = NULL;

		if (unlikely((edge = ip_validate_mbuf(mbuf, ip)) != 0))
			goto next;

		switch (e->domain) {
		case ETH_DOMAIN_LOOPBACK:
		case ETH_DOMAIN_LOCAL:
			// Packet sent to our ethernet address.
			break;
		case ETH_DOMAIN_BROADCAST:
		case ETH_DOMAIN_MULTICAST:
			// Non unicast ethernet destination. No need for a route lookup.
			edge = LOCAL;
			goto next;
		case ETH_DOMAIN_OTHER:
		case ETH_DOMAIN_UNKNOWN:
			// Drop all packets not sent to our ethernet address
			edge = OTHER_HOST;
			goto next;
		}

		nh = fib4_lookup(iface->vrf_id, ip->dst_addr);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		edge = nh_type_edges[nh->type];
		if (edge != FORWARD)
			goto next;

		// If the resolved next hop is local and the destination IP is ourselves,
		// send to ip_local.
		if (nh->flags & GR_NH_F_LOCAL && ip->dst_addr == nh->ipv4)
			edge = LOCAL;
		else if (e->domain == ETH_DOMAIN_LOOPBACK)
			edge = OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		// Store the resolved next hop for ip_output to avoid a second route lookup.
		d = ip_output_mbuf_data(mbuf);
		d->nh = nh;
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void ip_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV4), "ip_input");
	loopback_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV4), "ip_input");
}

static struct rte_node_register input_node = {
	.name = "ip_input",

	.process = ip_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip_forward",
		[OUTPUT] = "ip_output",
		[LOCAL] = "ip_input_local",
		[NO_ROUTE] = "ip_error_dest_unreach",
		[BAD_CHECKSUM] = "ip_input_bad_checksum",
		[BAD_LENGTH] = "ip_input_bad_length",
		[BAD_VERSION] = "ip_input_bad_version",
		[OTHER_HOST] = "ip_input_other_host",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.register_callback = ip_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_input_bad_checksum);
GR_DROP_REGISTER(ip_input_bad_length);
GR_DROP_REGISTER(ip_input_bad_version);
GR_DROP_REGISTER(ip_input_other_host);

#ifdef __GROUT_UNIT_TEST__
#include <gr_cmocka.h>

int gr_rte_log_type;
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
mock_func(rte_edge_t, gr_node_attach_parent(const char *, const char *));
mock_func(const struct nexthop *, fib4_lookup(uint16_t, ip4_addr_t));
mock_func(void, fib4_lookup_x4(uint16_t, ip4_addr_t, ip4_addr_t, ip4_addr_t, ip4_addr_t, const struct nexthop *[4]));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(int, trace_ip_format(char *, size_t, const struct rte_ipv4_hdr *, size_t));
mock_func(void, gr_eth_input_add_type(rte_be16_t, const char *));
mock_func(void, loopback_input_add_type(rte_be16_t, const char *));

struct fake_mbuf {
	struct rte_ipv4_hdr ipv4_hdr;
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static void ipv4_init_default_mbuf(struct fake_mbuf *fake_mbuf) {
	memset(fake_mbuf, 0, sizeof(struct fake_mbuf));
	fake_mbuf->ipv4_hdr.ihl = 5;
	fake_mbuf->ipv4_hdr.version = 4;
	fake_mbuf->ipv4_hdr.total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr));
	fake_mbuf->ipv4_hdr.type_of_service = 0;
	fake_mbuf->ipv4_hdr.packet_id = 1;
	fake_mbuf->ipv4_hdr.fragment_offset = 0;
	fake_mbuf->ipv4_hdr.time_to_live = 64;
	fake_mbuf->ipv4_hdr.next_proto_id = IPPROTO_RAW;
	fake_mbuf->ipv4_hdr.hdr_checksum = 0;
	fake_mbuf->ipv4_hdr.src_addr = RTE_IPV4(0, 3, 0, 1);
	fake_mbuf->ipv4_hdr.dst_addr = RTE_IPV4(1, 9, 8, 6);

	fake_mbuf->mbuf.buf_addr = &fake_mbuf->ipv4_hdr;
	fake_mbuf->mbuf.data_len = sizeof(struct rte_ipv4_hdr);
	fake_mbuf->mbuf.pkt_len = sizeof(struct rte_ipv4_hdr);
	fake_mbuf->mbuf.next = NULL;
	fake_mbuf->mbuf.nb_segs = 1;
	fake_mbuf->mbuf.ol_flags = 0;
	fake_mbuf->mbuf.packet_type = RTE_PTYPE_L3_IPV4;

	eth_input_mbuf_data(&fake_mbuf->mbuf)->domain = ETH_DOMAIN_OTHER;
}

static void ip_input_invalid_mbuf_len(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv4_init_default_mbuf(&fake_mbuf);

	fake_mbuf.ipv4_hdr.hdr_checksum = rte_ipv4_cksum(&fake_mbuf.ipv4_hdr);
	fake_mbuf.mbuf.data_len = sizeof(struct rte_ipv4_hdr) / 2;
	expect_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip_input_process(NULL, NULL, &obj, 1);
}

static void ip_input_invalid_cksum(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv4_init_default_mbuf(&fake_mbuf);

	fake_mbuf.ipv4_hdr.hdr_checksum = 0x666;
	expect_value(rte_node_enqueue_x1, next, BAD_CHECKSUM);
	ip_input_process(NULL, NULL, &obj, 1);
}

static void ip_input_invalid_version(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv4_init_default_mbuf(&fake_mbuf);

	fake_mbuf.ipv4_hdr.version = 5;
	fake_mbuf.ipv4_hdr.hdr_checksum = rte_ipv4_cksum(&fake_mbuf.ipv4_hdr);
	expect_value(rte_node_enqueue_x1, next, BAD_VERSION);
	ip_input_process(NULL, NULL, &obj, 1);
}

static void ip_input_invalid_ihl(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv4_init_default_mbuf(&fake_mbuf);

	fake_mbuf.ipv4_hdr.version = 3;
	fake_mbuf.ipv4_hdr.hdr_checksum = rte_raw_cksum(
		&fake_mbuf.ipv4_hdr, sizeof(struct rte_ipv4_hdr)
	);
	expect_value(rte_node_enqueue_x1, next, BAD_CHECKSUM);
	ip_input_process(NULL, NULL, &obj, 1);
}

static void ip_input_invalid_total_length(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv4_init_default_mbuf(&fake_mbuf);

	fake_mbuf.ipv4_hdr.total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) / 2);
	fake_mbuf.ipv4_hdr.hdr_checksum = rte_ipv4_cksum(&fake_mbuf.ipv4_hdr);
	expect_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip_input_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ip_input_invalid_mbuf_len),
		cmocka_unit_test(ip_input_invalid_cksum),
		cmocka_unit_test(ip_input_invalid_version),
		cmocka_unit_test(ip_input_invalid_ihl),
		cmocka_unit_test(ip_input_invalid_total_length),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
