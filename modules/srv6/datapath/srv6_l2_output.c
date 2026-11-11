// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

// SRv6 L2 service output: the egress node of the SRv6 bridge members.
//
// Frames the bridge forwards to an SRv6 L2 service port (known unicast
// from FDB entries, or BUM for flood-role ports) are encapsulated
// toward the port's remote SID with H.Encaps.L2 (SRH + Ethernet payload)
// or H.Encaps.L2.Red (single SID in the destination address, no SRH),
// then routed to the remote locator by the underlay.
//
// The outer header only depends on the port encapsulation config and on
// the underlay egress (the source address): it is pre-built once per
// (port, worker, underlay nexthop) and cached in the port info. The
// underlay route lookup stays per packet, so ECMP and route changes are
// honored exactly like the VXLAN encapsulation.

#include "graph.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "mbuf.h"
#include "nexthop.h"
#include "rxtx.h"
#include "srv6.h"

#include <gr_srv6.h>

#include <string.h>

enum {
	IP6_OUTPUT = 0,
	NO_SID,
	NO_ROUTE,
	NO_HEADROOM,
	EDGE_COUNT,
};

struct trace_srv6_l2_data {
	uint16_t encap_vrf_id;
	gr_srv6_encap_behavior_t encap;
	struct rte_ipv6_addr sid;
};

static int trace_srv6_l2_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_l2_data *t = data;
	size_t n = 0;
	SAFE_BUF(snprintf, len, "h.encaps%s.l2", t->encap == SR_H_ENCAPS_RED ? ".red" : "");
	SAFE_BUF(snprintf, len, " vrf=%u sid=" IP6_F, t->encap_vrf_id, &t->sid);
	return n;
err:
	return -1;
}

static uint16_t srv6_l2_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop_info_l3 *l3;
	const struct nexthop *underlay;
	const struct iface_info_sr6 *sr6;
	struct sr6_encap_tpl *tpl;
	struct iface_mbuf_data *d;
	struct rte_ipv6_hdr *outer_ip6;
	struct rte_mbuf *m;
	uint16_t plen;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		sr6 = iface_info_sr6(d->iface);

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_l2_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->encap_vrf_id = sr6->encap_vrf_id;
			t->encap = sr6->encap;
			t->sid = sr6->remote_sid;
		}

		if (rte_ipv6_addr_is_unspec(&sr6->remote_sid)) {
			// No remote SID programmed: the service is down.
			edge = NO_SID;
			goto next;
		}

		// Resolve the underlay nexthop toward the remote locator.
		underlay = fib6_lookup(
			sr6->encap_vrf_id, GR_IFACE_ID_UNDEF, &sr6->remote_sid, m->hash.rss
		);
		if (underlay == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		l3_mbuf_data(m)->nh = underlay;

		// This worker is the only writer of its cache slot: rebuild the
		// outer header when the port encapsulation changed (generation)
		// or when the underlay nexthop changed (ECMP, route update).
		tpl = &sr6->tpl[rte_lcore_id()];
		if (unlikely(tpl->gen != sr6->tpl_gen || tpl->nh != underlay)) {
			const struct nexthop *src_nh;
			struct rte_ipv6_routing_ext *srh;
			bool full = sr6->encap != SR_H_ENCAPS_RED;

			// Resolve the encapsulation source address from the
			// underlay egress interface (global SRv6 tunnel source).
			src_nh = sr_tunsrc_get(underlay->iface_id, &sr6->remote_sid);
			if (src_nh == NULL) {
				edge = NO_ROUTE;
				goto next;
			}
			l3 = nexthop_info_l3(src_nh);

			outer_ip6 = (struct rte_ipv6_hdr *)tpl->hdr;
			ip6_set_fields(
				outer_ip6,
				0,
				full ? IPPROTO_ROUTING : IPPROTO_ETHERNET,
				&l3->ipv6,
				&sr6->remote_sid
			);
			if (full) {
				// H.Encaps.L2: keep the SRH on the wire, the
				// segment is also the outer destination address.
				srh = (struct rte_ipv6_routing_ext *)(outer_ip6 + 1);
				srh->next_hdr = IPPROTO_ETHERNET;
				srh->hdr_len = (sizeof(*srh) + sizeof(sr6->remote_sid)) / 8 - 1;
				srh->type = RTE_IPV6_SRCRT_TYPE_4;
				srh->segments_left = 0;
				srh->flags = 0;
				srh->last_entry = 0;
				((struct rte_ipv6_addr *)(srh + 1))[0] = sr6->remote_sid;
				tpl->hdr_len = sizeof(*outer_ip6) + sizeof(*srh) + sizeof(sr6->remote_sid);
			} else {
				// H.Encaps.L2.Red: the single SID is the outer
				// destination address, no SRH.
				tpl->hdr_len = sizeof(*outer_ip6);
			}
			tpl->nh = underlay;
			tpl->gen = sr6->tpl_gen;
		}

		// Prepend the cached header and patch the per-packet payload
		// length (the only per-packet field of the outer header).
		plen = rte_pktmbuf_pkt_len(m);
		outer_ip6 = gr_mbuf_prepend(m, outer_ip6, tpl->hdr_len - sizeof(*outer_ip6));
		if (unlikely(outer_ip6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		memcpy(outer_ip6, tpl->hdr, tpl->hdr_len);
		outer_ip6->payload_len = rte_cpu_to_be_16(plen + tpl->hdr_len - sizeof(*outer_ip6));
		edge = IP6_OUTPUT;

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_l2_output_register(void) {
	iface_output_type_register(GR_IFACE_TYPE_SR6, "srv6_l2_output");
}

static struct rte_node_register srv6_l2_output_node = {
	.name = "srv6_l2_output",

	.process = srv6_l2_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP6_OUTPUT] = "ip6_output",
		[NO_SID] = "srv6_l2_output_no_sid",
		[NO_ROUTE] = "srv6_l2_output_no_route",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info srv6_l2_output_info = {
	.node = &srv6_l2_output_node,
	.type = GR_NODE_T_L2,
	.trace_format = trace_srv6_l2_format,
	.register_callback = srv6_l2_output_register,
};

GR_NODE_REGISTER(srv6_l2_output_info);

GR_DROP_REGISTER(srv6_l2_output_no_sid);
GR_DROP_REGISTER(srv6_l2_output_no_route);
