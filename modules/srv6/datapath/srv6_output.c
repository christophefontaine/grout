// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "graph.h"
#include "ip4_datapath.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "nexthop.h"
#include "srv6.h"

#include <gr_srv6.h>

#include <string.h>

//
// srv6 source node. encapsulate traffic
//
// The outer header only depends on the nexthop encapsulation config
// and on the underlay egress (the source address when no explicit
// encapsulation source is configured): it is pre-built once per
// (nexthop, worker, underlay nexthop) and cached in the nexthop
// snapshot. The underlay route lookup stays per packet, so ECMP and
// route changes are honored. The two bytes that depend on the inner
// packet family (the outer protocol, and the SRH next header when
// present) are patched per packet, so a single slot serves both
// families.

enum {
	IP6_OUTPUT = 0,
	INVALID,
	NO_ROUTE,
	NO_HEADROOM,
	EDGE_COUNT,
};

// Scratch slot for the (practically unreachable) case of a worker
// lcore id beyond the snapshot slot count: never cached, rebuilt for
// every packet.
#define SR6_OUTPUT_SCRATCH_MAX                                                                 \
	(sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_ipv6_routing_ext)                     \
	 + GR_SRV6_ROUTE_SEGLIST_COUNT_MAX * sizeof(struct rte_ipv6_addr))
struct sr6_output_scratch {
	struct sr6_l3_encap_tpl tpl;
	uint8_t hdr[SR6_OUTPUT_SCRATCH_MAX];
};
static __thread struct sr6_output_scratch scratch;

struct trace_srv6_data {
	gr_srv6_encap_behavior_t encap;
	sr_encap_flags_t flags;
	uint16_t n_seglist;
	struct rte_ipv6_addr seg0;
	struct rte_ipv6_addr encap_src;
};

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	size_t n = 0;
	SAFE_BUF(snprintf, len, "h.encaps%s", t->encap == SR_H_ENCAPS_RED ? ".red" : "");
	if (t->flags & SR_ENCAP_F_SRC)
		SAFE_BUF(snprintf, len, " encap_src=" IP6_F, &t->encap_src);
	SAFE_BUF(snprintf, len, " n_segs=%u seg[0]=" IP6_F, t->n_seglist, &t->seg0);
	return n;
err:
	return -1;
}

// called from 'ip6_output' or 'ip_output' node
static uint16_t
srv6_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct sr6_output_cache *cache;
	struct sr6_l3_encap_tpl *tpl;
	struct rte_ipv6_routing_ext *srh;
	struct rte_ipv6_hdr *outer_ip6;
	const struct nexthop *underlay;
	bool cached, full;
	uint8_t proto, n_omitted_segs;
	struct rte_mbuf *m;
	uint32_t plen;
	uint16_t lcore;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		underlay = l3_mbuf_data(m)->nh;
		cache = nexthop_info_srv6_output(underlay)->cache;

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->encap = cache->encap;
			t->flags = cache->flags;
			t->n_seglist = cache->n_seglist;
			t->seg0 = cache->seglist[0];
			t->encap_src = cache->encap_src;
		}

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			struct rte_ipv4_hdr *inner_ip4;
			inner_ip4 = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
			plen = rte_be_to_cpu_16(inner_ip4->total_length);
			proto = IPPROTO_IPIP;

		} else if (m->packet_type & RTE_PTYPE_L3_IPV6) {
			struct rte_ipv6_hdr *inner_ip6;
			inner_ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
			plen = rte_be_to_cpu_16(inner_ip6->payload_len) + sizeof(*inner_ip6);
			proto = IPPROTO_IPV6;

		} else {
			edge = INVALID;
			goto next;
		}

		// Resolve the underlay nexthop toward the first segment.
		underlay = fib6_lookup(underlay->vrf_id, GR_IFACE_ID_UNDEF, cache->seglist, m->hash.rss);
		if (underlay == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		l3_mbuf_data(m)->nh = underlay;

		// This worker is the only writer of its cache slot: rebuild the
		// header when the encapsulation changed (generation) or when the
		// underlay nexthop changed (ECMP, route update).
		lcore = rte_lcore_id();
		cached = lcore < cache->n_slots;
		if (cached) {
			tpl = (struct sr6_l3_encap_tpl *)
				((uint8_t *)cache + cache->slots_off + lcore * cache->stride);
		} else {
			tpl = &scratch.tpl;
		}
		if (!cached || unlikely(tpl->gen != sr6_output_tpl_gen)
		    || (!(cache->flags & SR_ENCAP_F_SRC) && tpl->nh != underlay)) {
			const struct rte_ipv6_addr *src;

			full = cache->encap != SR_H_ENCAPS_RED;
			n_omitted_segs = full ? 0 : 1;

			outer_ip6 = (struct rte_ipv6_hdr *)tpl->hdr;
			if (cache->n_seglist > n_omitted_segs) {
				struct rte_ipv6_addr *segments;
				uint16_t k;

				// H.Encaps: keep the SRH on the wire. Its next
				// header is patched per packet (inner family).
				srh = (struct rte_ipv6_routing_ext *)(outer_ip6 + 1);
				srh->hdr_len = (sizeof(*srh)
						+ (cache->n_seglist - n_omitted_segs)
							  * sizeof(cache->seglist[0]))
					       / 8 - 1;
				srh->type = RTE_IPV6_SRCRT_TYPE_4;
				srh->segments_left = cache->n_seglist - 1;
				// flags aliases the whole word: last_entry, flag and tag
				srh->flags = 0;
				srh->last_entry = cache->n_seglist - 1 - n_omitted_segs;

				segments = PAYLOAD(srh);
				for (k = n_omitted_segs; k < cache->n_seglist; k++)
					segments[cache->n_seglist - k - 1] = cache->seglist[k];
				tpl->hdr_len = sizeof(*outer_ip6) + (srh->hdr_len + 1) * 8;
			} else {
				// H.Encaps.Red with a single segment: the SID is
				// the outer destination address, no SRH. The
				// protocol is patched per packet.
				tpl->hdr_len = sizeof(*outer_ip6);
			}

			if (cache->flags & SR_ENCAP_F_SRC) {
				src = &cache->encap_src;
				tpl->nh = NULL;
			} else {
				const struct nexthop *src_nh =
					sr_tunsrc_get(underlay->iface_id, &cache->seglist[0]);
				if (src_nh == NULL) {
					edge = NO_ROUTE;
					goto next;
				}
				src = &nexthop_info_l3(src_nh)->ipv6;
				tpl->nh = underlay;
			}
			// The protocol byte is patched per packet (inner family).
			ip6_set_fields(outer_ip6, 0, 0, src, &cache->seglist[0]);
			tpl->gen = sr6_output_tpl_gen;
		}

		// Prepend the cached header, patch the per-packet fields: the
		// payload length and the family-dependent protocol bytes.
		outer_ip6 = gr_mbuf_prepend(m, outer_ip6, tpl->hdr_len - sizeof(*outer_ip6));
		if (unlikely(outer_ip6 == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		memcpy(outer_ip6, tpl->hdr, tpl->hdr_len);
		outer_ip6->payload_len = rte_cpu_to_be_16(plen + tpl->hdr_len - sizeof(*outer_ip6));
		if (tpl->hdr_len == sizeof(*outer_ip6)) {
			outer_ip6->proto = proto;
		} else {
			srh = (struct rte_ipv6_routing_ext *)(outer_ip6 + 1);
			outer_ip6->proto = IPPROTO_ROUTING;
			srh->next_hdr = proto;
		}
		edge = IP6_OUTPUT;

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_output_register(void) {
	ip_output_register_nexthop_type(GR_NH_T_SR6_OUTPUT, "sr6_output");
	ip6_output_register_nexthop_type(GR_NH_T_SR6_OUTPUT, "sr6_output");
}

static struct rte_node_register srv6_output_node = {
	.name = "sr6_output",

	.process = srv6_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP6_OUTPUT] = "ip6_output",
		[INVALID] = "sr6_pkt_invalid",
		[NO_ROUTE] = "sr6_source_no_route",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info srv6_output_info = {
	.node = &srv6_output_node,
	.type = GR_NODE_T_L3,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_output_register,
};

GR_NODE_REGISTER(srv6_output_info);

GR_DROP_REGISTER(sr6_pkt_invalid);
GR_DROP_REGISTER(sr6_source_no_route);
