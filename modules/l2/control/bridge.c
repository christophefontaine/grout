// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2_control.h"

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_module.h>

#include <errno.h>
#include <string.h>

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

// Global bridge domain storage
struct l2_bridge_domain *bridge_domains[GR_L2_MAX_BRIDGE_DOMAINS] = {NULL};
rte_spinlock_t bridge_domains_lock = RTE_SPINLOCK_INITIALIZER;

// MAC table hash parameters
static const struct rte_hash_parameters mac_table_params = {
	.entries = GR_L2_MAX_MAC_ENTRIES_PER_DOMAIN,
	.key_len = sizeof(struct l2_mac_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = SOCKET_ID_ANY,
};

uint32_t l2_get_timestamp(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)ts.tv_sec;
}

int l2_validate_domain_id(uint16_t domain_id) {
	if (domain_id >= GR_L2_MAX_BRIDGE_DOMAINS) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

struct l2_bridge_domain *l2_bridge_domain_get(uint16_t domain_id) {
	if (l2_validate_domain_id(domain_id) < 0)
		return NULL;
	
	rte_spinlock_lock(&bridge_domains_lock);
	struct l2_bridge_domain *domain = bridge_domains[domain_id];
	rte_spinlock_unlock(&bridge_domains_lock);
	
	return domain;
}

struct l2_bridge_domain *l2_bridge_domain_create(const struct gr_l2_bridge_domain *config) {
	if (l2_validate_domain_id(config->domain_id) < 0)
		return NULL;
	
	rte_spinlock_lock(&bridge_domains_lock);
	
	if (bridge_domains[config->domain_id] != NULL) {
		rte_spinlock_unlock(&bridge_domains_lock);
		errno = EEXIST;
		return NULL;
	}
	
	struct l2_bridge_domain *domain = rte_zmalloc(NULL, sizeof(*domain), 0);
	if (domain == NULL) {
		rte_spinlock_unlock(&bridge_domains_lock);
		errno = ENOMEM;
		return NULL;
	}
	
	// Initialize domain configuration
	domain->domain_id = config->domain_id;
	snprintf(domain->name, sizeof(domain->name), "%s", config->name);
	domain->learning_timeout = config->learning_timeout ?: GR_L2_DEFAULT_LEARNING_TIMEOUT;
	domain->flood_unknown = config->flood_unknown;
	domain->flood_bcast = config->flood_bcast;
	domain->flood_mcast = config->flood_mcast;
	domain->l3_iface_id = config->l3_iface_id;
	
	// Create MAC learning table
	char hash_name[64];
	snprintf(hash_name, sizeof(hash_name), "l2_mac_%u", config->domain_id);
	
	struct rte_hash_parameters params = mac_table_params;
	params.name = hash_name;
	
	domain->mac_table = rte_hash_create(&params);
	if (domain->mac_table == NULL) {
		LOG(ERR, "Failed to create MAC table for domain %u", config->domain_id);
		rte_free(domain);
		rte_spinlock_unlock(&bridge_domains_lock);
		errno = ENOMEM;
		return NULL;
	}
	
	rte_spinlock_init(&domain->lock);
	domain->n_entries = 0;
	domain->last_cleanup = l2_get_timestamp();
	
	bridge_domains[config->domain_id] = domain;
	rte_spinlock_unlock(&bridge_domains_lock);
	
	LOG(INFO, "Created L2 bridge domain %u ('%s')", config->domain_id, config->name);
	return domain;
}

int l2_bridge_domain_destroy(uint16_t domain_id) {
	if (l2_validate_domain_id(domain_id) < 0)
		return -1;
	
	rte_spinlock_lock(&bridge_domains_lock);
	
	struct l2_bridge_domain *domain = bridge_domains[domain_id];
	if (domain == NULL) {
		rte_spinlock_unlock(&bridge_domains_lock);
		errno = ENOENT;
		return -1;
	}
	
	// Clean up MAC table
	if (domain->mac_table) {
		rte_hash_free(domain->mac_table);
	}
	
	bridge_domains[domain_id] = NULL;
	rte_spinlock_unlock(&bridge_domains_lock);
	
	rte_free(domain);
	
	LOG(INFO, "Destroyed L2 bridge domain %u", domain_id);
	return 0;
}

int l2_bridge_domain_update(const struct gr_l2_bridge_domain *config) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(config->domain_id);
	if (domain == NULL)
		return -1;
	
	rte_spinlock_lock(&domain->lock);
	
	// Update configuration
	snprintf(domain->name, sizeof(domain->name), "%s", config->name);
	domain->learning_timeout = config->learning_timeout ?: GR_L2_DEFAULT_LEARNING_TIMEOUT;
	domain->flood_unknown = config->flood_unknown;
	domain->flood_bcast = config->flood_bcast;
	domain->flood_mcast = config->flood_mcast;
	domain->l3_iface_id = config->l3_iface_id;
	
	rte_spinlock_unlock(&domain->lock);
	
	LOG(INFO, "Updated L2 bridge domain %u ('%s')", config->domain_id, config->name);
	return 0;
}
