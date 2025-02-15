// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_l4.h"
#include "gr_vxlan.h"
#include "vxlan_priv.h"

#include <gr_datapath.h>
#include <gr_eth.h>
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
	ETH = 0,
	IP,
	IP6,
	BAD_NEXTPROTO,
	BAD_FRAME,
	NO_TUNNEL,
	EDGE_COUNT,
};

int trace_vxlan_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_vxlan_data *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	return snprintf(buf, len, "iface=%s vni=%u", iface ? iface->name : "[deleted]", t->vni);
}

static uint16_t vxlan_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct eth_input_mbuf_data *eth_data;
	struct rte_vxlan_hdr *vxlan;
	struct rte_mbuf *mbuf;
	struct iface *iface;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		vxlan = rte_pktmbuf_mtod(mbuf, struct rte_vxlan_hdr*);

		if ((vxlan->flag_p && vxlan->flag_ver != 0) || vxlan->flag_i == 0) {
			edge = BAD_FRAME;
			goto next;
		}

		iface = vxlan_get_iface(rte_be_to_cpu_32(vxlan->vx_vni), mbuf_data(mbuf)->iface->vrf_id);
		if (iface == NULL) {
			edge = NO_TUNNEL;
			goto next;
		}

		if (vxlan->flag_p) {
			edge = ETH;
			goto next;
		}

		switch(vxlan->proto) {
			case 0x01:
			case 0x02:
				mbuf->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_NONE;
				eth_data = eth_input_mbuf_data(mbuf);
				eth_data->iface = iface;
				eth_data->domain = ETH_DOMAIN_LOCAL;
				edge = vxlan->proto == 0x01 ? IP : IP6;
				break;
			case 0x03: edge = ETH; break;
			default: edge = BAD_NEXTPROTO; break;
		}
		
next:
		rte_pktmbuf_adj(mbuf, sizeof(*vxlan));
		if (gr_mbuf_is_traced(mbuf) || (iface && iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct trace_vxlan_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->iface_id = iface ? iface->id : 0;
			t->vni = rte_be_to_cpu_32(vxlan->vx_vni);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static struct rte_node_register input_node = {
	.name = "vxlan_input",
	.process = vxlan_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH] = "eth_input",
		[IP] = "ip_input",
		[IP6] = "ip6_input",
		[BAD_NEXTPROTO] = "vxlan_bad_nextproto",
		[BAD_FRAME] = "vxlan_bad_frame",
		[NO_TUNNEL] = "vxlan_no_tunnel",
	},
};

static void vxlan_input_register(void) {
	// Should we expose this dport as a runtime param ?
	l4_input_register_port(IPPROTO_UDP, RTE_VXLAN_DEFAULT_PORT, "vxlan_input");
	l4_input_register_port(IPPROTO_UDP, RTE_VXLAN_GPE_DEFAULT_PORT, "vxlan_input");
}

static struct gr_node_info info = {
	.node = &input_node,
	.register_callback = vxlan_input_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(vxlan_bad_nextproto);
GR_DROP_REGISTER(vxlan_bad_frame);
GR_DROP_REGISTER(vxlan_no_tunnel);
