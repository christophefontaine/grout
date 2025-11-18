// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_eth.h>
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

enum edges {
	L3_INPUT = 0, // Send to L3 processing (bridge interface)
	PORT_OUTPUT, // Send to specific port
	FLOOD, // Flood to all bridge members
	DROP, // Drop packet
	EDGE_COUNT
};

struct l2_bridge_trace {
	uint16_t bridge_id;
	uint16_t src_iface;
	uint16_t dst_iface;
	struct rte_ether_addr src_mac;
	struct rte_ether_addr dst_mac;
	uint8_t action; // 0=learn, 1=forward, 2=flood, 3=to_bridge_iface, 4=drop
};

static uint16_t
l2_bridge_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface_info_port *port_info;
	struct bridge_info *bridge;
	struct rte_ether_hdr *eth;
	struct rte_mbuf *mbuf;
	struct iface *iface, *bridge_iface;
	uint16_t bridge_id, dst_iface_id;
	rte_edge_t edge;
	bool dst_found;
	__rte_unused bool src_learned;
	int ret;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		iface = (struct iface *)mbuf_data(mbuf)->iface;
		bridge_id = iface->domain_id;

		// Get bridge information
		bridge = bridge_get(bridge_id);
		if (bridge == NULL) {
			edge = DROP;
			goto next;
		}

		eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

		// Learn source MAC address (for dynamic learning)
		src_learned = false;
		if (!rte_is_zero_ether_addr(&eth->src_addr)) {
			ret = mac_entry_lookup(bridge_id, &eth->src_addr, &dst_iface_id);
			if (ret < 0) {
				// MAC not found, learn it
				ret = mac_entry_add(
					bridge_id, iface->id, &eth->src_addr, GR_L2_MAC_DYNAMIC
				);
				if (ret == 0) {
					src_learned = true;
				}
			} else if (dst_iface_id != iface->id) {
				// MAC moved to different interface, update
				ret = mac_entry_add(
					bridge_id, iface->id, &eth->src_addr, GR_L2_MAC_DYNAMIC
				);
				if (ret == 0) {
					src_learned = true;
				}
			}
		}

		// Handle special destination addresses
		if (rte_is_broadcast_ether_addr(&eth->dst_addr)
		    || rte_is_multicast_ether_addr(&eth->dst_addr)) {
			// Broadcast/multicast - flood to all bridge members except source
			edge = FLOOD;
			goto next;
		}

		// Check if destination is the bridge interface itself
		bridge_iface = bridge_get_iface(bridge_id);
		if (bridge_iface != NULL) {
			struct rte_ether_addr bridge_mac;
			if (iface_get_eth_addr(bridge_iface->id, &bridge_mac) == 0
			    && rte_is_same_ether_addr(&eth->dst_addr, &bridge_mac)) {
				// Packet destined for bridge interface - send to L3 processing
				mbuf_data(mbuf)->iface = bridge_iface;
				edge = L3_INPUT;
				goto next;
			}
		}

		// Look up destination MAC
		dst_found = false;
		ret = mac_entry_lookup(bridge_id, &eth->dst_addr, &dst_iface_id);
		if (ret == 0) {
			// MAC found - forward to specific interface
			dst_found = true;

			// Don't forward back to source interface
			if (dst_iface_id == iface->id) {
				edge = DROP;
				goto next;
			}

			// Get destination interface
			struct iface *dst_iface = iface_from_id(dst_iface_id);
			if (dst_iface == NULL || dst_iface->type != GR_IFACE_TYPE_PORT) {
				edge = DROP;
				goto next;
			}

			// Set up for port output
			port_info = iface_info_port(dst_iface);
			mbuf->port = port_info->port_id;
			mbuf_data(mbuf)->iface = dst_iface;
			edge = PORT_OUTPUT;
		} else {
			// MAC not found
			if (bridge->config.flood_unknown) {
				// Flood unknown unicast
				edge = FLOOD;
			} else {
				// Drop unknown unicast
				edge = DROP;
			}
		}

next:
		// Add trace information if tracing is enabled
		if (gr_mbuf_is_traced(mbuf)) {
			struct l2_bridge_trace *trace = gr_mbuf_trace_add(
				mbuf, node, sizeof(*trace)
			);
			trace->bridge_id = bridge_id;
			trace->src_iface = iface->id;
			trace->dst_iface = (edge == PORT_OUTPUT) ? dst_iface_id : 0;
			trace->src_mac = eth->src_addr;
			trace->dst_mac = eth->dst_addr;

			if (edge == DROP)
				trace->action = 4;
			else if (edge == L3_INPUT)
				trace->action = 3;
			else if (edge == FLOOD)
				trace->action = 2;
			else if (dst_found)
				trace->action = 1;
			else
				trace->action = 0;
		}

		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static int l2_bridge_trace_format(char *buf, size_t len, const void *data, size_t data_len) {
	const struct l2_bridge_trace *t = data;
	const char *actions[] = {"learn", "forward", "flood", "to_bridge"};
	int n = 0;

	if (data_len < sizeof(*t))
		return -1;

	n = snprintf(
		buf,
		len,
		"bridge=%u src_iface=%u dst_iface=%u action=%s src=" ETH_F " dst=" ETH_F,
		t->bridge_id,
		t->src_iface,
		t->dst_iface,
		actions[t->action % 4],
		&t->src_mac,
		&t->dst_mac
	);

	return n;
}

static struct rte_node_register l2_bridge_node = {
	.name = "l2_bridge",
	.process = l2_bridge_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[L3_INPUT] = "eth_input",
		[PORT_OUTPUT] = "port_output",
		[FLOOD] = "l2_flood",
		[DROP] = "l2_bridge_drop",
	},
};

static void l2_bridge_register(void) {
	register_interface_mode(GR_IFACE_MODE_L2_BRIDGE, "l2_bridge");
	eth_output_register_interface_type(GR_IFACE_TYPE_BRIDGE, "l2_bridge");
}

static struct gr_node_info info = {
	.node = &l2_bridge_node,
	.register_callback = l2_bridge_register,
	.trace_format = l2_bridge_trace_format,
};

GR_NODE_REGISTER(info);
GR_DROP_REGISTER(l2_bridge_drop);
