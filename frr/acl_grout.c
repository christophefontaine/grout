// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#include "acl_grout.h"
#include "if_map.h"
#include "log_grout.h"
#include "zebra_dplane_grout.h"

#include <gr_acl.h>
#include <gr_infra.h>

#include <errno.h>
#include <lib/frr_pthread.h>
#include <lib/hash.h>
#include <lib/if.h>
#include <lib/linklist.h>
#include <lib/typesafe.h>
#include <lib/vrf.h>
#include <stdlib.h>
#include <string.h>
#include <zebra/zebra_dplane.h>
#include <zebra/zebra_pbr.h>
#include <zebra/zebra_router.h>

// ---------------------------------------------------------------------------
// ipset name -> grout set id map
//
// FRR identifies ACL match sets by name (zebra_pbr_ipset.ipset_name) and
// references them by name from ipset entry and iptable updates, while grout
// identifies objects by numeric id. The plugin reuses FRR's per-object
// `unique` counters as grout ids (as is already done for nexthop group ids)
// and keeps this map to resolve the name references.

PREDECL_HASH(acl_set_name);

struct acl_set_mapping {
	struct acl_set_name_item item;
	uint32_t set_id;
	char name[ZEBRA_IPSET_NAME_SIZE];
};

static int acl_set_name_cmp(const struct acl_set_mapping *a, const struct acl_set_mapping *b) {
	return strcmp(a->name, b->name);
}

static uint32_t acl_set_name_hash(const struct acl_set_mapping *mapping) {
	return string_hash_make(mapping->name);
}

DECLARE_HASH(acl_set_name, struct acl_set_mapping, item, acl_set_name_cmp, acl_set_name_hash);

static struct acl_set_name_head acl_set_mappings = INIT_HASH(acl_set_mappings);

// The map is written from the dplane thread and cleared from the zebra main
// thread (grout_reconnect), hence the lock.
static pthread_mutex_t acl_map_mtx = PTHREAD_MUTEX_INITIALIZER;

static void acl_set_mapping_name(struct acl_set_mapping *mapping, const char *name) {
	snprintf(mapping->name, sizeof(mapping->name), "%s", name);
}

static void acl_set_mapping_add(const char *name, uint32_t set_id) {
	struct acl_set_mapping *mapping;

	mapping = XCALLOC(MTYPE_GROUT_MEM, sizeof(*mapping));
	mapping->set_id = set_id;
	acl_set_mapping_name(mapping, name);

	frr_with_mutex(&acl_map_mtx) {
		struct acl_set_mapping *existing;

		existing = acl_set_name_add(&acl_set_mappings, mapping);
		if (existing && existing != mapping)
			XFREE(MTYPE_GROUT_MEM, mapping); // keep the existing mapping
	}
}

static void acl_set_mapping_del(const char *name) {
	struct acl_set_mapping key = {0};
	struct acl_set_mapping *found;

	acl_set_mapping_name(&key, name);

	frr_with_mutex(&acl_map_mtx) {
		found = acl_set_name_find(&acl_set_mappings, &key);
		if (found) {
			acl_set_name_del(&acl_set_mappings, found);
			XFREE(MTYPE_GROUT_MEM, found);
		}
	}
}

static uint32_t acl_set_mapping_lookup(const char *name) {
	struct acl_set_mapping key = {0};
	struct acl_set_mapping *found;
	uint32_t set_id = 0;

	acl_set_mapping_name(&key, name);

	frr_with_mutex(&acl_map_mtx) {
		found = acl_set_name_find(&acl_set_mappings, &key);
		if (found)
			set_id = found->set_id;
	}

	return set_id;
}

void clear_acl_mappings(void) {
	struct acl_set_mapping *mapping;

	frr_with_mutex(&acl_map_mtx) {
		frr_each_safe(acl_set_name, &acl_set_mappings, mapping) {
			acl_set_name_del(&acl_set_mappings, mapping);
			XFREE(MTYPE_GROUT_MEM, mapping);
		}
	}
}

// ---------------------------------------------------------------------------
// dplane -> grout API translation

static addr_family_t family_frr_to_grout(uint8_t family) {
	if (family == AF_INET)
		return GR_AF_IP4;
	if (family == AF_INET6)
		return GR_AF_IP6;
	return GR_AF_UNSPEC;
}

static void prefix_to_acl_net(struct gr_acl_net *net, const struct prefix *p) {
	net->af = family_frr_to_grout(p->family);
	net->prefixlen = p->prefixlen;
	if (p->family == AF_INET)
		net->ip4 = p->u.prefix4.s_addr;
	else if (p->family == AF_INET6)
		memcpy(&net->ip6, &p->u.prefix6, sizeof(net->ip6));
}

enum zebra_dplane_result grout_add_del_ipset(struct zebra_dplane_ctx *ctx) {
	bool new = dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_ADD;
	struct zebra_pbr_ipset ipset;

	dplane_ctx_get_pbr_ipset(ctx, &ipset);

	gr_log_debug(
		"%s ipset %s unique %u type %s family %s vrf %u",
		new ? "add" : "del",
		ipset.ipset_name,
		ipset.unique,
		zebra_pbr_ipset_type2str(ipset.type),
		family2str(ipset.family),
		ipset.vrf_id
	);

	if (new) {
		struct gr_acl_set_add_req req = {
			.exist_ok = true,
		};

		req.set.set_id = ipset.unique;
		req.set.vrf_id = vrf_frr_to_grout(dplane_ctx_get_vrf(ctx));
		req.set.af = family_frr_to_grout(ipset.family);
		// ipset type and gr_acl_set_type_t share the same values
		req.set.type = (gr_acl_set_type_t)ipset.type;

		if (req.set.af == GR_AF_UNSPEC) {
			gr_log_err("unsupported family %u, skip", ipset.family);
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		if (grout_client_send_recv(GR_ACL_SET_ADD, sizeof(req), &req, NULL) < 0)
			return ZEBRA_DPLANE_REQUEST_FAILURE;

		acl_set_mapping_add(ipset.ipset_name, ipset.unique);
	} else {
		struct gr_acl_set_del_req req = {
			.set_id = ipset.unique,
			.missing_ok = true,
		};

		if (grout_client_send_recv(GR_ACL_SET_DEL, sizeof(req), &req, NULL) < 0)
			return ZEBRA_DPLANE_REQUEST_FAILURE;

		acl_set_mapping_del(ipset.ipset_name);
	}

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result grout_add_del_ipset_entry(struct zebra_dplane_ctx *ctx) {
	bool new = dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_ENTRY_ADD;
	struct zebra_pbr_ipset_entry entry;
	struct zebra_pbr_ipset ipset;
	uint32_t set_id;

	dplane_ctx_get_pbr_ipset_entry(ctx, &entry);
	dplane_ctx_get_pbr_ipset(ctx, &ipset);

	gr_log_debug(
		"%s ipset entry %u in %s: %pFX -> %pFX proto %u sport %u-%u dport %u-%u",
		new ? "add" : "del",
		entry.unique,
		ipset.ipset_name,
		&entry.src,
		&entry.dst,
		entry.proto,
		entry.src_port_min,
		entry.src_port_max,
		entry.dst_port_min,
		entry.dst_port_max
	);

	set_id = acl_set_mapping_lookup(ipset.ipset_name);
	if (set_id == 0) {
		gr_log_err("ipset %s not created by grout, skip", ipset.ipset_name);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (new) {
		struct gr_acl_entry_add_req req = {
			.exist_ok = true,
		};

		req.entry.set_id = set_id;
		req.entry.entry_id = entry.unique;
		prefix_to_acl_net(&req.entry.src, &entry.src);
		prefix_to_acl_net(&req.entry.dst, &entry.dst);
		req.entry.src_port_min = entry.src_port_min;
		req.entry.src_port_max = entry.src_port_max;
		req.entry.dst_port_min = entry.dst_port_min;
		req.entry.dst_port_max = entry.dst_port_max;
		req.entry.proto = entry.proto;

		if (req.entry.src.af == GR_AF_UNSPEC || req.entry.dst.af == GR_AF_UNSPEC) {
			gr_log_err("unsupported family, skip");
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		if (grout_client_send_recv(GR_ACL_ENTRY_ADD, sizeof(req), &req, NULL) < 0)
			return ZEBRA_DPLANE_REQUEST_FAILURE;
	} else {
		struct gr_acl_entry_del_req req = {
			.set_id = set_id,
			.entry_id = entry.unique,
			.missing_ok = true,
		};

		if (grout_client_send_recv(GR_ACL_ENTRY_DEL, sizeof(req), &req, NULL) < 0)
			return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

enum zebra_dplane_result grout_add_del_iptable(struct zebra_dplane_ctx *ctx) {
	bool new = dplane_ctx_get_op(ctx) == DPLANE_OP_IPTABLE_ADD;
	struct zebra_pbr_iptable iptable;

	dplane_ctx_get_pbr_iptable(ctx, &iptable);

	gr_log_debug(
		"%s iptable %u ipset %s action %s fwmark %u filter 0x%x family %s vrf %u",
		new ? "add" : "del",
		iptable.unique,
		iptable.ipset_name,
		iptable.action == ZEBRA_IPTABLES_DROP ? "drop" : "forward",
		iptable.fwmark,
		iptable.filter_bm,
		family2str(iptable.family),
		iptable.vrf_id
	);

	if (!new) {
		struct gr_acl_filter_del_req req = {
			.filter_id = iptable.unique,
			.missing_ok = true,
		};

		if (grout_client_send_recv(GR_ACL_FILTER_DEL, sizeof(req), &req, NULL) < 0)
			return ZEBRA_DPLANE_REQUEST_FAILURE;

		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	struct list *ifnames = iptable.interface_name_list;
	struct gr_acl_filter_add_req *req;
	unsigned int n_ifnames = ifnames ? ifnames->count : 0;
	size_t len = sizeof(*req) + n_ifnames * sizeof(req->filter.iface_ids[0]);
	uint32_t set_id = acl_set_mapping_lookup(iptable.ipset_name);
	addr_family_t af = family_frr_to_grout(iptable.family);
	struct listnode *node;
	const char *ifname;

	if (af == GR_AF_UNSPEC) {
		gr_log_err("unsupported family %u, skip", iptable.family);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (set_id == 0) {
		gr_log_err("ipset %s not created by grout, skip", iptable.ipset_name);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req->exist_ok = true;
	req->filter.filter_id = iptable.unique;
	req->filter.vrf_id = vrf_frr_to_grout(dplane_ctx_get_vrf(ctx));
	req->filter.set_id = set_id;
	// MATCH_*_SET and GR_ACL_MATCH_* share the same bit values
	req->filter.match_bm = iptable.filter_bm;
	req->filter.action = GR_ACL_ACTION_MARK;
	if (iptable.action == ZEBRA_IPTABLES_DROP)
		req->filter.action = GR_ACL_ACTION_DROP;
	req->filter.fwmark = iptable.fwmark;
	req->filter.pkt_len_min = iptable.pkt_len_min;
	req->filter.pkt_len_max = iptable.pkt_len_max;
	req->filter.tcp_flags = iptable.tcp_flags;
	req->filter.tcp_mask = iptable.tcp_mask_flags;
	req->filter.dscp = iptable.dscp_value;
	req->filter.fragment = iptable.fragment;
	req->filter.proto = iptable.protocol;
	req->filter.flow_label = iptable.flow_label;
	req->filter.af = af;

	// The interface name list is owned by the dplane ctx: only walk it
	// while the ctx is alive, i.e. from this handler.
	for (ALL_LIST_ELEMENTS_RO(ifnames, node, ifname)) {
		struct interface *ifp = if_lookup_by_name(ifname, iptable.vrf_id);
		uint16_t iface_id;

		if (ifp == NULL) {
			gr_log_warn("interface %s not found, skip", ifname);
			continue;
		}

		iface_id = ifindex_frr_to_grout(ifp->ifindex);
		if (iface_id == GR_IFACE_ID_UNDEF) {
			gr_log_warn("interface %s not managed by grout, skip", ifname);
			continue;
		}

		if (req->filter.n_ifaces >= n_ifnames)
			break; // be defensive, should not happen

		req->filter.iface_ids[req->filter.n_ifaces++] = iface_id;
	}

	if (grout_client_send_recv(GR_ACL_FILTER_ADD, len, req, NULL) < 0) {
		free(req);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	free(req);
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

// ---------------------------------------------------------------------------
// ACL resync
//
// Zebra owns the ACL state installed by BGP flowspec: on grout reconnect the
// plugin wipes its mappings and grout comes back empty, but nothing replays
// the objects (bgpd does not re-announce them on zebra events). Re-enqueue
// the dplane operations for the objects held by zebra so that they flow
// through the regular provider chain, i.e. through the translation above.
// The resulting notifications confirm the re-installation to bgpd.
//
// The operations are processed asynchronously by the dplane thread, which
// owns the grout API client used by the translations. This is safe as long
// as no other thread uses that client concurrently: the main thread sync
// steps all use the dedicated sync client.

static void grout_resync_ipset_cb(struct hash_bucket *bucket, void *) {
	struct zebra_pbr_ipset *ipset = bucket->data;

	(void)dplane_pbr_ipset_add(ipset);
}

static void grout_resync_ipset_entry_cb(struct hash_bucket *bucket, void *) {
	struct zebra_pbr_ipset_entry *entry = bucket->data;

	(void)dplane_pbr_ipset_entry_add(entry);
}

static void grout_resync_iptable_cb(struct hash_bucket *bucket, void *) {
	struct zebra_pbr_iptable *iptable = bucket->data;

	(void)dplane_pbr_iptable_add(iptable);
}

void grout_resync_acls(void) {
	unsigned int n_entries = hashcount(zrouter.ipset_entry_hash);
	unsigned int n_iptables = hashcount(zrouter.iptable_hash);
	unsigned int n_ipsets = hashcount(zrouter.ipset_hash);

	if (n_ipsets == 0 && n_entries == 0 && n_iptables == 0)
		return;

	gr_log_info(
		"resyncing %u ipsets, %u ipset entries and %u iptables into grout",
		n_ipsets,
		n_entries,
		n_iptables
	);

	// Enqueue in dependency order: ipsets first (their dplane results
	// rebuild the name -> set id map), then entries, then iptables. The
	// dplane processes updates in FIFO order.
	hash_iterate(zrouter.ipset_hash, grout_resync_ipset_cb, NULL);
	hash_iterate(zrouter.ipset_entry_hash, grout_resync_ipset_entry_cb, NULL);
	hash_iterate(zrouter.iptable_hash, grout_resync_iptable_cb, NULL);
}
