// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2_control.h"

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

static uint16_t l2_flood_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf, *clone;
	const struct iface *rx_iface, *iface;
	struct l2_bridge_domain *domain;
	const struct iface_info_port *port;
	rte_edge_t edge;
	uint16_t sent = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		rx_iface = mbuf_data(mbuf)->iface;

		// Get bridge domain
		domain = l2_bridge_domain_get(rx_iface->domain_id);
		if (unlikely(domain == NULL)) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// Find all interfaces in the same bridge domain
		bool first = true;
		iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			// Skip if not in same domain or same interface
			if (iface->mode != GR_IFACE_MODE_L2_BRIDGE ||
			    iface->domain_id != rx_iface->domain_id ||
			    iface->id == rx_iface->id) {
				continue;
			}

			// Skip if interface is down
			if (!(iface->flags & GR_IFACE_F_UP)) {
				continue;
			}

			// Skip L3 interface (handled separately by l2_switch)
			if (domain->l3_iface_id != 0 && iface->id == domain->l3_iface_id) {
				continue;
			}

			// Only handle physical ports for now
			if (iface->type != GR_IFACE_TYPE_PORT) {
				continue;
			}

			// Clone packet for all but the last interface
			if (first) {
				clone = mbuf;
				first = false;
			} else {
				clone = rte_pktmbuf_clone(mbuf, mbuf->pool);
				if (clone == NULL) {
					LOG(WARNING, "Failed to clone packet for flooding");
					continue;
				}
			}

			// Set output port
			port = (const struct iface_info_port *)iface->info;
			clone->port = port->port_id;
			edge = TX;

			// Update statistics
			struct iface_stats *tx_stats = iface_get_stats(rte_lcore_id(), iface->id);
			tx_stats->tx_packets++;
			tx_stats->tx_bytes += rte_pktmbuf_pkt_len(clone);

			if (gr_mbuf_is_traced(clone)) {
				gr_mbuf_trace_add(clone, node, 0);
			}
			rte_node_enqueue_x1(graph, node, edge, clone);
			sent++;
		}

		// If no interfaces were found, free the original packet
		if (first) {
			rte_pktmbuf_free(mbuf);
		}
	}

	return sent;
}

static struct rte_node_register l2_flood_node = {
	.name = "l2_flood",
	.process = l2_flood_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TX] = "port_tx",
		[NO_PORT] = "l2_flood_no_port",
	},
};

static struct gr_node_info info = {
	.node = &l2_flood_node,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_flood_no_port);
