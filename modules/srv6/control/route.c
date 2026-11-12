// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "event.h"
#include "module.h"
#include "rcu.h"
#include "srv6.h"

#include <gr_ip6.h>
#include <gr_srv6.h>

#include <rte_malloc.h>

// routes ////////////////////////////////////////////////////////////////
static bool srv6_output_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct sr6_output_cache *ad = nexthop_info_srv6_output(a)->cache;
	const struct sr6_output_cache *bd = nexthop_info_srv6_output(b)->cache;

	if (ad->encap != bd->encap)
		return false;

	if (!rte_ipv6_addr_eq(&ad->encap_src, &bd->encap_src))
		return false;

	if (ad->n_seglist != bd->n_seglist)
		return false;

	for (unsigned i = 0; i < ad->n_seglist; i++) {
		if (!rte_ipv6_addr_eq(&ad->seglist[i], &bd->seglist[i]))
			return false;
	}

	return true;
}

static int srv6_output_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_srv6_output *priv = nexthop_info_srv6_output(nh);
	const struct gr_nexthop_info_srv6 *pub = info;
	struct sr6_output_cache *cache, *old_cache;
	size_t stride, size;
	unsigned n_slots;

	// The API and FRR paths forward the segment list length without
	// validating it: bound it here (the CLI already does).
	if (pub->n_seglist == 0 || pub->n_seglist > GR_SRV6_ROUTE_SEGLIST_COUNT_MAX)
		return errno_set(EINVAL);

	// Build the datapath snapshot: the encapsulation config, the
	// segment list and one pre-built header slot per worker in a
	// single block, published with one pointer store. The control
	// plane reads the config through the same block.
	stride = RTE_ALIGN(sizeof(struct sr6_l3_encap_tpl) + SR6_ENCAP_HDR_CAP(pub->n_seglist),
			   RTE_CACHE_LINE_SIZE);
	n_slots = rte_lcore_count();
	size = sr6_output_slots_off(pub->n_seglist) + stride * n_slots;
	cache = rte_calloc(__func__, 1, size, RTE_CACHE_LINE_SIZE);
	if (cache == NULL)
		return errno_set(ENOMEM);

	cache->encap = pub->encap_behavior;
	cache->flags = rte_ipv6_addr_is_unspec(&pub->encap_src) ? 0 : SR_ENCAP_F_SRC;
	cache->n_seglist = pub->n_seglist;
	cache->encap_src = pub->encap_src;
	cache->stride = stride;
	cache->n_slots = n_slots;
	cache->slots_off = sr6_output_slots_off(pub->n_seglist);
	memcpy(cache->seglist, pub->seglist, pub->n_seglist * sizeof(struct rte_ipv6_addr));

	old_cache = priv->cache;
	priv->cache = cache;
	// A new configuration must never reuse a template built for the
	// previous one: the scratch fallback also keys its cache on the
	// snapshot pointer, which a recycled allocation can alias.
	sr6_output_tpl_invalidate();
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_free(old_cache);

	return 0;
}

static struct gr_nexthop *srv6_output_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct sr6_output_cache *cache = nexthop_info_srv6_output(nh)->cache;
	struct gr_nexthop_info_srv6 *sr6_pub;
	struct gr_nexthop *pub;

	*len = sizeof(*pub) + sizeof(*sr6_pub) + cache->n_seglist * sizeof(sr6_pub->seglist[0]);
	pub = malloc(*len);
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	sr6_pub = (struct gr_nexthop_info_srv6 *)pub->info;

	sr6_pub->encap_behavior = cache->encap;
	sr6_pub->encap_src = cache->encap_src;
	sr6_pub->n_seglist = cache->n_seglist;
	memcpy(sr6_pub->seglist, cache->seglist, sizeof(sr6_pub->seglist[0]) * sr6_pub->n_seglist);

	return pub;
}

static void srv6_output_nh_del(struct nexthop *nh) {
	struct nexthop_info_srv6_output *sr6 = nexthop_info_srv6_output(nh);
	rte_free(sr6->cache);
	sr6->cache = NULL;
}

// Bumped when the encapsulation source of the cached headers may have
// changed (tunnel source, underlay address). Starts at 1: the cache
// slots are zeroed at allocation, a generation of 0 must never match an
// unbuilt slot.
_Atomic(uint32_t) sr6_output_tpl_gen = 1;

_Atomic(struct nexthop *) tunsrc_nh = NULL;

static struct api_out srv6_tunsrc_clear(const void * /*request*/, struct api_ctx *) {
	struct nexthop *nh = tunsrc_nh;

	if (nh != NULL) {
		// Publish the clear before destroying the nexthop: a worker
		// must never resolve the tunnel source from a freed nexthop.
		atomic_store_explicit(&tunsrc_nh, NULL, memory_order_release);
		nexthop_decref(nh);
		// The cached encapsulation headers embed the tunnel source.
		sr6_output_tpl_invalidate();
	}

	return api_out(0, 0, NULL);
}

static struct api_out srv6_tunsrc_set(const void *request, struct api_ctx *ctx) {
	const struct gr_srv6_tunsrc_set_req *req = request;
	struct nexthop *nh, *old_nh;

	if (rte_ipv6_addr_is_unspec(&req->addr))
		return srv6_tunsrc_clear(NULL, ctx);

	if (tunsrc_nh != NULL) {
		struct nexthop_info_l3 *old = nexthop_info_l3(tunsrc_nh);
		if (rte_ipv6_addr_eq(&old->ipv6, &req->addr))
			return api_out(0, 0, NULL);
	}

	struct gr_nexthop_base base = {
		.type = GR_NH_T_L3,
		.iface_id = GR_IFACE_ID_UNDEF,
		.vrf_id = GR_VRF_ID_UNDEF,
		.origin = GR_NH_ORIGIN_INTERNAL,
	};
	struct gr_nexthop_info_l3 l3 = {
		.af = GR_AF_IP6,
		.flags = GR_NH_F_LOCAL | GR_NH_F_LINK,
		.state = GR_NH_S_REACHABLE,
		.ipv6 = req->addr,
		.prefixlen = 128,
	};

	if ((nh = nexthop_new(&base, &l3)) == NULL)
		return api_out(errno, 0, NULL);

	old_nh = tunsrc_nh;
	atomic_store_explicit(&tunsrc_nh, nh, memory_order_release);
	if (old_nh != NULL)
		nexthop_decref(old_nh);
	// The cached encapsulation headers embed the tunnel source.
	sr6_output_tpl_invalidate();

	return api_out(0, 0, NULL);
}

static struct api_out srv6_tunsrc_show(const void * /*request*/, struct api_ctx *) {
	struct gr_srv6_tunsrc_show_resp *resp;

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(-ENOMEM, 0, NULL);

	if (tunsrc_nh) {
		struct nexthop_info_l3 *l3 = nexthop_info_l3(tunsrc_nh);
		resp->addr = l3->ipv6;
	} else {
		resp->addr = (struct rte_ipv6_addr)RTE_IPV6_ADDR_UNSPEC;
	}

	return api_out(0, sizeof(*resp), resp);
}

// srv6 headend module /////////////////////////////////////////////////////

static struct nexthop_type_ops nh_ops = {
	.free = srv6_output_nh_del,
	.equal = srv6_output_nh_equal,
	.import_info = srv6_output_nh_import_info,
	.to_api = srv6_output_nh_to_api,
};

static void srv6_addr_event_handler(uint32_t /*event*/, const void * /*obj*/) {
	// An underlay address change may change the encapsulation source
	// address (the preferred address of the egress interface): rebuild
	// the cached headers.
	sr6_output_tpl_invalidate();
}

RTE_INIT(srv6_constructor) {
	api_handler(GR_SRV6_TUNSRC_SET, srv6_tunsrc_set);
	api_handler(GR_SRV6_TUNSRC_CLEAR, srv6_tunsrc_clear);
	api_handler(GR_SRV6_TUNSRC_SHOW, srv6_tunsrc_show);
	nexthop_type_ops_register(GR_NH_T_SR6_OUTPUT, &nh_ops);
	event_subscribe(GR_EVENT_IP6_ADDR_ADD, srv6_addr_event_handler);
	event_subscribe(GR_EVENT_IP6_ADDR_DEL, srv6_addr_event_handler);
}
