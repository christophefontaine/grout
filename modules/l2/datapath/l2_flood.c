// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

enum edges {
	PORT_OUTPUT = 0,
	DROP,
	EDGE_COUNT
};

struct l2_flood_trace {
	uint16_t bridge_id;
	uint16_t src_iface;
	uint16_t flood_count;
	struct rte_ether_addr dst_mac;
};

static uint16_t
l2_flood_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_port *port_info;
	struct rte_mbuf *mbuf, *clone;
	const struct iface *src_iface;
	uint16_t bridge_id, *member;
	struct bridge_info *bridge;
	struct iface *dst_iface;
	uint16_t flood_count;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		src_iface = mbuf_data(mbuf)->iface;
		bridge_id = src_iface->domain_id;
		flood_count = 0;

		// Get bridge information
		bridge = bridge_get(bridge_id);
		if (bridge == NULL) {
			edge = DROP;
			goto next;
		}

		// Flood to all bridge members except source interface
		gr_vec_foreach_ref (member, bridge->members) {
			if (*member == src_iface->id)
				continue; // Don't flood back to source

			dst_iface = iface_from_id(*member);
			if (dst_iface == NULL || dst_iface->type != GR_IFACE_TYPE_PORT)
				continue;

			if (!(dst_iface->flags & GR_IFACE_F_UP))
				continue; // Skip down interfaces

			// Clone packet for each destination (except the last one)
			if (flood_count == 0) {
				// Use original packet for first destination
				clone = mbuf;
			} else {
				// Clone packet for additional destinations
				clone = rte_pktmbuf_clone(mbuf, mbuf->pool);
				if (clone == NULL) {
					LOG(WARNING, "Failed to clone packet for flooding");
					continue;
				}

				// Copy mbuf metadata
				*mbuf_data(clone) = *mbuf_data(mbuf);
			}

			// Set up for port output
			port_info = iface_info_port(dst_iface);
			clone->port = port_info->port_id;
			mbuf_data(clone)->iface = dst_iface;

			// Update TX statistics
			struct iface_stats *tx_stats = iface_get_stats(
				rte_lcore_id(), dst_iface->id
			);
			tx_stats->tx_packets++;
			tx_stats->tx_bytes += rte_pktmbuf_pkt_len(clone);

			flood_count++;

			// Add trace information if tracing is enabled
			if (gr_mbuf_is_traced(clone)) {
				struct l2_flood_trace *trace = gr_mbuf_trace_add(
					clone, node, sizeof(*trace)
				);
				trace->bridge_id = bridge_id;
				trace->src_iface = src_iface->id;
				trace->flood_count = flood_count;

				struct rte_ether_hdr *eth = rte_pktmbuf_mtod(
					clone, struct rte_ether_hdr *
				);
				trace->dst_mac = eth->dst_addr;
			}

			rte_node_enqueue_x1(graph, node, PORT_OUTPUT, clone);
		}

		// If no flooding occurred, drop the original packet
		if (flood_count == 0) {
			edge = DROP;
		} else {
			// Original packet was used for flooding, don't enqueue it again
			continue;
		}

next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static int l2_flood_trace_format(char *buf, size_t len, const void *data, size_t data_len) {
	const struct l2_flood_trace *t = data;
	int n = 0;

	if (data_len < sizeof(*t))
		return -1;

	n = snprintf(
		buf,
		len,
		"bridge=%u src_iface=%u flood_count=%u dst=" ETH_F,
		t->bridge_id,
		t->src_iface,
		t->flood_count,
		&t->dst_mac
	);

	return n;
}

static struct rte_node_register l2_flood_node = {
	.name = "l2_flood",
	.process = l2_flood_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[PORT_OUTPUT] = "port_output",
		[DROP] = "l2_flood_drop",
	},
};

static struct gr_node_info info = {
	.node = &l2_flood_node,
	.trace_format = l2_flood_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_flood_drop);
