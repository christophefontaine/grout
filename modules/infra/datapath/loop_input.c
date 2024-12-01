// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr.h>
#include <gr_control_input.h>
#include <gr_graph.h>
#include <gr_loopback.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>

static control_input_t control_to_loop_input;

control_input_t loopback_get_control_id(void) {
	return control_to_loop_input;
}

enum {
	IP_INPUT,
	IP6_INPUT,
	EDGE_COUNT,
};

static uint16_t
loop_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_mbuf *ip;
	struct rte_mbuf *mbuf;
	int edge;

	for (unsigned i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = control_input_mbuf_data(mbuf)->data;

		if (gr_trace_all_enabled())
			gr_mbuf_trace_add(ip, node, 0);

		if (ip->packet_type == RTE_PTYPE_L3_IPV4)
			edge = IP_INPUT;
		else
			edge = IP6_INPUT;

		rte_node_enqueue_x1(graph, node, edge, ip);
		rte_pktmbuf_free(mbuf);
	}
	return nb_objs;
}

static struct rte_node_register loop_input_node = {
	.name = "loop_input",
	.process = loop_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		//FIXME: use something similar to icmp_local_send instead of forward
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
	},
};

static void loop_input_register(void) {
	control_to_loop_input = gr_control_input_register_handler("loop_input");
}

static struct gr_node_info info = {
	.node = &loop_input_node,
	.register_callback = loop_input_register,
};

GR_NODE_REGISTER(info);
