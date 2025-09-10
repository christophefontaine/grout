// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2_control.h"

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_trace.h>

#include <rte_ether.h>
#include <rte_mbuf.h>

enum edges {
	FLOOD = 0,     // Flood to all interfaces in domain
	OUTPUT,        // Send to specific output interface
	L3_INPUT,      // Send to L3 processing (for bridge's L3 interface)
	DROP,          // Drop packet
	EDGE_COUNT
};

static uint16_t l2_switch_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	struct rte_ether_hdr *eth_hdr;
	const struct iface *rx_iface;
	struct l2_bridge_domain *domain;
	uint16_t dst_iface_id;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		rx_iface = mbuf_data(mbuf)->iface;
		edge = DROP;

		// Get ethernet header
		eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		if (unlikely(eth_hdr == NULL)) {
			goto next;
		}

		// Get bridge domain for this interface
		domain = l2_bridge_domain_get(rx_iface->domain_id);
		if (unlikely(domain == NULL)) {
			LOG(ERR, "No bridge domain %u for interface %u", 
			    rx_iface->domain_id, rx_iface->id);
			goto next;
		}

		// Learn source MAC
		if (!rte_is_zero_ether_addr(&eth_hdr->src_addr) && 
		    !rte_is_broadcast_ether_addr(&eth_hdr->src_addr) &&
		    !rte_is_multicast_ether_addr(&eth_hdr->src_addr)) {
			l2_mac_learn(rx_iface->domain_id, &eth_hdr->src_addr, 
				     rx_iface->id, false);
		}

		// Handle special destination addresses
		if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr)) {
			// Broadcast - flood to all ports in domain (except source)
			if (domain->flood_bcast) {
				edge = FLOOD;
			} else {
				edge = DROP;
			}
			goto next;
		}

		if (rte_is_multicast_ether_addr(&eth_hdr->dst_addr)) {
			// Multicast - flood to all ports in domain (except source)
			if (domain->flood_mcast) {
				edge = FLOOD;
			} else {
				edge = DROP;
			}
			goto next;
		}

		// Check if destination matches L3 interface MAC first
		bool to_l3 = false;
		if (domain->l3_iface_id != 0) {
			const struct iface *l3_iface = iface_from_id(domain->l3_iface_id);
			if (l3_iface != NULL && l3_iface->type == GR_IFACE_TYPE_PORT) {
				const struct iface_info_port *port_info = 
					(const struct iface_info_port *)l3_iface->info;
				if (rte_is_same_ether_addr(&eth_hdr->dst_addr, &port_info->mac)) {
					to_l3 = true;
				}
			}
		}

		if (to_l3) {
			// Packet is destined for the bridge's L3 interface
			edge = L3_INPUT;
		} else {
			// Unicast destination - lookup in MAC table
			int ret = l2_mac_lookup(rx_iface->domain_id, &eth_hdr->dst_addr, &dst_iface_id);
			if (ret == 0) {
				if (dst_iface_id != rx_iface->id) {
					// Different interface - forward to it
					// Store dest interface in the packet itself by overriding port field
					mbuf->port = dst_iface_id;
					edge = OUTPUT;
				} else {
					// Same interface as source - drop (loop prevention)
					edge = DROP;
				}
			} else {
				// MAC not found - flood if enabled
				if (domain->flood_unknown) {
					edge = FLOOD;
				} else {
					edge = DROP;
				}
			}
		}

next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void l2_switch_register(void) {
	register_interface_mode(GR_IFACE_MODE_L2_BRIDGE, "l2_switch");
}

static struct rte_node_register l2_switch_node = {
	.name = "l2_switch",
	.process = l2_switch_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FLOOD] = "l2_flood",
		[OUTPUT] = "l2_output",
		[L3_INPUT] = "eth_input", // Route to L3 processing
		[DROP] = "l2_switch_drop",
	},
};

static struct gr_node_info info = {
	.node = &l2_switch_node,
	.register_callback = l2_switch_register,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_switch_drop);
