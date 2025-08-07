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

// called from 'ip6_output' or 'ip_output' node
static uint16_t
srv6_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct trace_srv6_data *t = NULL;
	struct rte_ipv6_hdr *outer_ip6;
	struct srv6_encap_data *d;
	const struct nexthop *nh;
	struct rte_mbuf *m;
	rte_edge_t edge;
	uint32_t plen;
	uint8_t proto;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		if (gr_mbuf_is_traced(m))
			t = gr_mbuf_trace_add(m, node, sizeof(*t));

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			struct rte_ipv4_hdr *inner_ip4;

			nh = ip_output_mbuf_data(m)->nh;
			if (t != NULL) {
				t->dest4.ip = nh->ipv4;
				t->dest4.prefixlen = nh->prefixlen;
				t->is_dest6 = false;
			}
			inner_ip4 = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			plen = rte_be_to_cpu_16(inner_ip4->total_length);
			proto = IPPROTO_IPIP;

		} else if (m->packet_type & RTE_PTYPE_L3_IPV6) {
			struct rte_ipv6_hdr *inner_ip6;

			nh = ip6_output_mbuf_data(m)->nh;
			if (t != NULL) {
				t->dest6.ip = nh->ipv6;
				t->dest6.prefixlen = nh->prefixlen;
				t->is_dest6 = true;
			}
			inner_ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			plen = rte_be_to_cpu_16(inner_ip6->payload_len);
			proto = IPPROTO_IPV6;

		} else {
			edge = INVALID;
			goto next;
		}

		d = srv6_encap_nh_priv(nh)->d;
		if (d == NULL) {
			edge = INVALID;
			goto next;
		}

		// Encapsulate with another IPv6 header
		outer_ip6 = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, d->len);
		if (unlikely(outer_ip6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		plen += d->len - sizeof(*outer_ip6);
		memcpy(outer_ip6, &d->template_hdr, d->len);

		// Resolve nexthop for the encapsulated packet.
		nh = fib6_lookup(nh->vrf_id, GR_IFACE_ID_UNDEF, &d->dst);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		ip6_output_mbuf_data(m)->nh = nh;

		nh = sr_tunsrc_get(nh->iface_id, &nh->ipv6);
		if (nh == NULL) {
			// cannot output packet on interface that does not have ip6 addr
			edge = NO_ROUTE;
			goto next;
		}

		ip6_set_fields(outer_ip6, plen, proto, &nh->ipv6, &d->dst);
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
	.trace_format = trace_srv6_format,
	.register_callback = srv6_output_register,
};

GR_NODE_REGISTER(srv6_output_info);

GR_DROP_REGISTER(sr6_pkt_invalid);
GR_DROP_REGISTER(sr6_source_no_route);
