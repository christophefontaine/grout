// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth_input.h>
#include <gr_graph.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

enum edges {
	FORWARD = 0,
	LOCAL,
	DEST_UNREACH,
	NOT_MEMBER,
	OTHER_HOST,
	BAD_VERSION,
	BAD_ADDR,
	BAD_LENGTH,
	EDGE_COUNT,
};

static uint16_t
ip6_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip6_output_mbuf_data *d;
	struct eth_input_mbuf_data *e;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *mbuf;
	struct nexthop6 *nh;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
		e = eth_input_mbuf_data(mbuf);
		d = ip6_output_mbuf_data(mbuf);
		iface = e->iface;
		nh = NULL;

		if (rte_ipv6_check_version(ip)) {
			edge = BAD_VERSION;
			goto next;
		}

		if (rte_ipv6_addr_is_mcast(&ip->src_addr)
		    || rte_ipv6_addr_is_unspec(&ip->dst_addr)) {
			edge = BAD_ADDR;
			goto next;
		}

		if (unlikely(rte_ipv6_addr_is_mcast(&ip->dst_addr))) {
			switch (rte_ipv6_mc_scope(&ip->dst_addr)) {
			case RTE_IPV6_MC_SCOPE_RESERVED:
				// RFC4291 2.7:
				// Nodes must not originate a packet to a multicast address
				// whose scope field contains the reserved value 0; if such
				// a packet is received, it must be silently dropped.
			case RTE_IPV6_MC_SCOPE_IFACELOCAL:
				// This should only happen if the input interface is a loopback
				// interface. For now, we do not have support for these.
				edge = BAD_ADDR;
				break;
			default:
				nh = ip6_mcast_get_member(iface->id, &ip->dst_addr);
				if (nh == NULL)
					edge = NOT_MEMBER;
				else
					edge = LOCAL;
			}
			goto next;
		}

		switch (e->eth_dst) {
		case ETH_DST_LOCAL:
			// Packet sent to our ethernet address.
			break;
		case ETH_DST_BROADCAST:
		case ETH_DST_MULTICAST:
			// Non unicast ethernet destination. No need for a route lookup.
			edge = LOCAL;
			goto next;
		case ETH_DST_OTHER:
		default:
			// Drop all packets not sent to our ethernet address
			edge = OTHER_HOST;
			goto next;
		}

		nh = ip6_route_lookup(iface->vrf_id, &ip->dst_addr);
		if (nh == NULL) {
			edge = DEST_UNREACH;
			goto next;
		}

		// If the resolved next hop is local and the destination IP is ourselves,
		// send to ip6_local.
		if (nh->flags & GR_IP6_NH_F_LOCAL && rte_ipv6_addr_eq(&ip->dst_addr, &nh->ip))
			edge = LOCAL;
		else
			edge = FORWARD;

next:
		// Store the resolved next hop for ip6_output to avoid a second route lookup.
		d->nh = nh;
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void ip6_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV6), "ip6_input");
}

static struct rte_node_register input_node = {
	.name = "ip6_input",

	.process = ip6_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip6_forward",
		[LOCAL] = "ip6_input_local",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
		[NOT_MEMBER] = "ip6_input_not_member",
		[OTHER_HOST] = "ip6_input_other_host",
		[BAD_VERSION] = "ip6_input_bad_version",
		[BAD_ADDR] = "ip6_input_bad_addr",
		[BAD_LENGTH] = "ip6_input_bad_length",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.register_callback = ip6_input_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip6_input_not_member);
GR_DROP_REGISTER(ip6_input_other_host);
GR_DROP_REGISTER(ip6_input_bad_version);
GR_DROP_REGISTER(ip6_input_bad_addr);
GR_DROP_REGISTER(ip6_input_bad_length);
