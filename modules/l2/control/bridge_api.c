// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2_control.h"
#include "../api/gr_l2.h"

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_module.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

// Bridge domain management API handlers

static struct api_out l2_bridge_add(const void *request, void **response) {
	const struct gr_l2_bridge_add_req *req = request;
	struct gr_l2_bridge_add_resp *resp;
	struct l2_bridge_domain *domain;

	// Validate input
	if (req->domain.domain_id >= GR_L2_MAX_BRIDGE_DOMAINS) {
		return api_out(EINVAL, 0);
	}

	// Create bridge domain
	domain = l2_bridge_domain_create(&req->domain);
	if (domain == NULL) {
		return api_out(errno, 0);
	}

	// Prepare response
	resp = calloc(1, sizeof(*resp));
	if (resp == NULL) {
		l2_bridge_domain_destroy(req->domain.domain_id);
		return api_out(ENOMEM, 0);
	}

	resp->domain_id = domain->domain_id;
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out l2_bridge_del(const void *request, void ** /* response */) {
	const struct gr_l2_bridge_del_req *req = request;

	if (l2_bridge_domain_destroy(req->domain_id) < 0) {
		return api_out(errno, 0);
	}

	return api_out(0, 0);
}

static struct api_out l2_bridge_set(const void *request, void ** /* response */) {
	const struct gr_l2_bridge_set_req *req = request;

	if (l2_bridge_domain_update(&req->domain) < 0) {
		return api_out(errno, 0);
	}

	return api_out(0, 0);
}

static struct api_out l2_bridge_get(const void *request, void **response) {
	const struct gr_l2_bridge_get_req *req = request;
	struct gr_l2_bridge_get_resp *resp;
	struct l2_bridge_domain *domain;

	domain = l2_bridge_domain_get(req->domain_id);
	if (domain == NULL) {
		return api_out(errno, 0);
	}

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL) {
		return api_out(ENOMEM, 0);
	}

	// Copy domain configuration
	resp->domain.domain_id = domain->domain_id;
	snprintf(resp->domain.name, sizeof(resp->domain.name), "%s", domain->name);
	resp->domain.learning_timeout = domain->learning_timeout;
	resp->domain.flood_unknown = domain->flood_unknown;
	resp->domain.flood_bcast = domain->flood_bcast;
	resp->domain.flood_mcast = domain->flood_mcast;
	resp->domain.l3_iface_id = domain->l3_iface_id;

	*response = resp;
	return api_out(0, sizeof(*resp));
}

static struct api_out l2_bridge_list(const void * /* request */, void **response) {
	struct gr_l2_bridge_list_resp *resp;
	size_t resp_size;
	uint16_t n_domains = 0;

	// Count existing domains
	rte_spinlock_lock(&bridge_domains_lock);
	for (uint16_t i = 0; i < GR_L2_MAX_BRIDGE_DOMAINS; i++) {
		if (bridge_domains[i] != NULL) {
			n_domains++;
		}
	}

	resp_size = sizeof(*resp) + n_domains * sizeof(resp->domains[0]);
	resp = calloc(1, resp_size);
	if (resp == NULL) {
		rte_spinlock_unlock(&bridge_domains_lock);
		return api_out(ENOMEM, 0);
	}

	resp->n_domains = 0;
	for (uint16_t i = 0; i < GR_L2_MAX_BRIDGE_DOMAINS && resp->n_domains < n_domains; i++) {
		struct l2_bridge_domain *domain = bridge_domains[i];
		if (domain != NULL) {
			struct gr_l2_bridge_domain *dom_resp = &resp->domains[resp->n_domains];
			
			dom_resp->domain_id = domain->domain_id;
			snprintf(dom_resp->name, sizeof(dom_resp->name), "%s", domain->name);
			dom_resp->learning_timeout = domain->learning_timeout;
			dom_resp->flood_unknown = domain->flood_unknown;
			dom_resp->flood_bcast = domain->flood_bcast;
			dom_resp->flood_mcast = domain->flood_mcast;
			dom_resp->l3_iface_id = domain->l3_iface_id;
			
			resp->n_domains++;
		}
	}
	
	rte_spinlock_unlock(&bridge_domains_lock);

	*response = resp;
	return api_out(0, resp_size);
}

// MAC table management API handlers

static struct api_out l2_mac_add(const void *request, void ** /* response */) {
	const struct gr_l2_mac_add_req *req = request;

	if (l2_mac_learn(req->entry.domain_id, &req->entry.mac, 
			 req->entry.iface_id, req->entry.is_static) < 0) {
		return api_out(errno, 0);
	}

	return api_out(0, 0);
}

static struct api_out l2_mac_del(const void *request, void ** /* response */) {
	const struct gr_l2_mac_del_req *req = request;

	if (l2_mac_delete(req->domain_id, &req->mac) < 0) {
		return api_out(errno, 0);
	}

	return api_out(0, 0);
}

static struct api_out l2_mac_flush_api(const void *request, void ** /* response */) {
	const struct gr_l2_mac_flush_req *req = request;

	int flushed = l2_mac_flush(req->domain_id, req->iface_id);
	if (flushed < 0) {
		return api_out(errno, 0);
	}

	return api_out(0, 0);
}

// Interface mode setting (already implemented in xconnect.c but needs L2 bridge support)
static struct api_out l2_mode_set(const void *request, void ** /* response */) {
	const struct gr_l2_iface_mode_req *req = request;
	struct iface *iface;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL) {
		return api_out(ENODEV, 0);
	}

	// Clean all L3 related info when switching away from L3
	if (req->mode != GR_IFACE_MODE_L3) {
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
	}

	// Set interface mode and domain
	iface->mode = req->mode;
	iface->domain_id = req->domain_id;

	// When switching to L2 bridge mode, enable promiscuous mode
	if (req->mode == GR_IFACE_MODE_L2_BRIDGE) {
		// Enable promiscuous mode for L2 switching
		iface->flags |= GR_IFACE_F_PROMISC;
		
		// Trigger interface reconfiguration to apply promiscuous mode
		gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, iface);
		
		LOG(INFO, "Interface %u set to L2 bridge mode (domain %u)", 
		    req->iface_id, req->domain_id);
	} else if (req->mode == GR_IFACE_MODE_L3) {
		// Disable promiscuous mode when switching back to L3
		iface->flags &= ~GR_IFACE_F_PROMISC;
		
		// Trigger interface reconfiguration to apply changes
		gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, iface);
		gr_event_push(GR_EVENT_IFACE_STATUS_UP, iface);
		
		LOG(INFO, "Interface %u set to L3 mode", req->iface_id);
	}

	return api_out(0, 0);
}

// API handler registration
static struct gr_api_handler l2_bridge_add_handler = {
	.name = "l2 bridge add",
	.request_type = GR_L2_BRIDGE_ADD,
	.callback = l2_bridge_add,
};

static struct gr_api_handler l2_bridge_del_handler = {
	.name = "l2 bridge del",
	.request_type = GR_L2_BRIDGE_DEL,
	.callback = l2_bridge_del,
};

static struct gr_api_handler l2_bridge_set_handler = {
	.name = "l2 bridge set",
	.request_type = GR_L2_BRIDGE_SET,
	.callback = l2_bridge_set,
};

static struct gr_api_handler l2_bridge_get_handler = {
	.name = "l2 bridge get",
	.request_type = GR_L2_BRIDGE_GET,
	.callback = l2_bridge_get,
};

static struct gr_api_handler l2_bridge_list_handler = {
	.name = "l2 bridge list",
	.request_type = GR_L2_BRIDGE_LIST,
	.callback = l2_bridge_list,
};

static struct gr_api_handler l2_mac_add_handler = {
	.name = "l2 mac add",
	.request_type = GR_L2_MAC_ADD,
	.callback = l2_mac_add,
};

static struct gr_api_handler l2_mac_del_handler = {
	.name = "l2 mac del",
	.request_type = GR_L2_MAC_DEL,
	.callback = l2_mac_del,
};

static struct gr_api_handler l2_mac_flush_handler = {
	.name = "l2 mac flush",
	.request_type = GR_L2_MAC_FLUSH,
	.callback = l2_mac_flush_api,
};

static struct gr_api_handler l2_mode_set_handler = {
	.name = "l2 mode set",
	.request_type = GR_L2_MODE_SET,
	.callback = l2_mode_set,
};

RTE_INIT(l2_api_constructor) {
	gr_register_api_handler(&l2_bridge_add_handler);
	gr_register_api_handler(&l2_bridge_del_handler);
	gr_register_api_handler(&l2_bridge_set_handler);
	gr_register_api_handler(&l2_bridge_get_handler);
	gr_register_api_handler(&l2_bridge_list_handler);
	gr_register_api_handler(&l2_mac_add_handler);
	gr_register_api_handler(&l2_mac_del_handler);
	gr_register_api_handler(&l2_mac_flush_handler);
	gr_register_api_handler(&l2_mode_set_handler);
}
