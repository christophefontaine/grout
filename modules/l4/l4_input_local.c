// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum edges {
	REDIRECT = 0,
	NO_IFACE,
	EDGE_COUNT,
};

static uint16_t
l4_redirect_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct mbuf_data *d;
	int edge = NO_IFACE;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		d = mbuf_data(mbuf);
		d->iface = get_vrf_iface(d->iface->vrf_id);
		if (d->iface)
			edge = REDIRECT;
		rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
	}

	rte_node_enqueue(graph, node, edge, objs, nb_objs);
	return nb_objs;
}

static struct rte_node_register tcp_input_local_node = {
	.name = "tcp_input_local",
	.process = l4_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loop_output",
		[NO_IFACE] = "no_loop_iface",
	},
};

static struct rte_node_register udp_input_local_node = {
	.name = "udp_input_local",
	.process = l4_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loop_output",
		[NO_IFACE] = "no_loop_iface",
	},
};

static struct rte_node_register sctp_input_local_node = {
	.name = "sctp_input_local",
	.process = l4_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loop_output",
		[NO_IFACE] = "no_loop_iface",
	},
};

static void udp_input_local_register(void) {
	ip_input_local_add_proto(IPPROTO_UDP, "udp_input_local");
	ip6_input_local_add_proto(IPPROTO_UDP, "udp_input_local");
}

static void tcp_input_local_register(void) {
	ip_input_local_add_proto(IPPROTO_TCP, "tcp_input_local");
	ip6_input_local_add_proto(IPPROTO_TCP, "tcp_input_local");
}

static void sctp_input_local_register(void) {
	ip_input_local_add_proto(IPPROTO_SCTP, "sctp_input_local");
	ip6_input_local_add_proto(IPPROTO_SCTP, "sctp_input_local");
}

static struct gr_node_info info_udp = {
	.node = &udp_input_local_node,
	.register_callback = udp_input_local_register,
};

static struct gr_node_info info_tcp = {
	.node = &tcp_input_local_node,
	.register_callback = tcp_input_local_register,
};

static struct gr_node_info info_sctp = {
	.node = &sctp_input_local_node,
	.register_callback = sctp_input_local_register,
};

GR_NODE_REGISTER(info_udp);
GR_NODE_REGISTER(info_tcp);
GR_NODE_REGISTER(info_sctp);
GR_DROP_REGISTER(no_loop_iface);
