// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_trace.h>

#include <rte_mbuf.h>

enum edges {
	TX = 0,       // Send to port_tx
	NO_PORT,      // No physical port
	EDGE_COUNT
};

static uint16_t l2_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	const struct iface *dst_iface;
	const struct iface_info_port *port;
	rte_edge_t edge;
	uint16_t dst_iface_id;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		dst_iface_id = mbuf->port; // Get dest interface from port field
		edge = NO_PORT;

		// Get destination interface
		dst_iface = iface_from_id(dst_iface_id);
		if (unlikely(dst_iface == NULL)) {
			LOG(ERR, "Invalid destination interface %u", dst_iface_id);
			goto next;
		}

		// Check if interface is up
		if (!(dst_iface->flags & GR_IFACE_F_UP)) {
			goto next;
		}

		// Handle based on interface type
		switch (dst_iface->type) {
		case GR_IFACE_TYPE_PORT:
			port = (const struct iface_info_port *)dst_iface->info;
			mbuf->port = port->port_id;
			edge = TX;
			
			// Update TX statistics
			struct iface_stats *tx_stats = iface_get_stats(rte_lcore_id(), dst_iface->id);
			tx_stats->tx_packets++;
			tx_stats->tx_bytes += rte_pktmbuf_pkt_len(mbuf);
			break;
			
		default:
			LOG(WARNING, "Unsupported interface type %u for L2 output", dst_iface->type);
			edge = NO_PORT;
			break;
		}

next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register l2_output_node = {
	.name = "l2_output",
	.process = l2_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TX] = "port_tx",
		[NO_PORT] = "l2_output_no_port",
	},
};

static struct gr_node_info info = {
	.node = &l2_output_node,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_output_no_port);
