// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <linux/if_tun.h>

enum edges {
	REDIRECT = 0,
	NO_IFACE,
	EDGE_COUNT,
};

static uint16_t ip_redirect_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct iface_info_port *info;
	struct rte_ipv4_hdr *ip;
	const struct iface *tun;
	struct rte_mbuf *mbuf;
	uint16_t port_id = 0;
	int edge = NO_IFACE;

	tun = gr_get_tun_redirect();

	if (tun) {
		info = (struct iface_info_port *)tun->info;
		port_id = info->port_id;
		edge = REDIRECT;
	}

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		mbuf->port = port_id;
		rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
	}

	rte_node_enqueue(graph, node, edge, objs, nb_objs);
	return nb_objs;
}

static struct rte_node_register redirect_node = {
	.name = "ip_redirect",
	.process = ip_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "port_tx",
		[NO_IFACE] = "no_tun",
	},
};

static void tcp_udp_register(void) {
	// Redirect UDP and TCP
	ip_input_local_add_proto(IPPROTO_TCP, "ip_redirect");
	ip_input_local_add_proto(IPPROTO_UDP, "ip_redirect");
}

static struct gr_node_info info = {
	.node = &redirect_node,
	.register_callback = tcp_udp_register,
	//.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(no_tun);
