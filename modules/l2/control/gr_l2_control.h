// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include "../api/gr_l2.h"

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

// Bridge domain structure
struct l2_bridge_domain {
	uint16_t domain_id;
	char name[64];
	uint16_t learning_timeout;
	bool flood_unknown;
	bool flood_bcast;
	bool flood_mcast;
	uint16_t l3_iface_id;
	
	// MAC learning table
	struct rte_hash *mac_table;
	rte_spinlock_t lock;
	uint32_t n_entries;
	uint32_t last_cleanup; // Last cleanup timestamp
};

// MAC table key structure
struct l2_mac_key {
	struct rte_ether_addr mac;
	uint16_t domain_id;
};

// MAC table entry structure (stored in hash table)
struct l2_mac_entry_internal {
	uint16_t iface_id;
	uint32_t timestamp;
	bool is_static;
};

// Global bridge domain management
extern struct l2_bridge_domain *bridge_domains[GR_L2_MAX_BRIDGE_DOMAINS];
extern rte_spinlock_t bridge_domains_lock;

// Bridge domain management functions
struct l2_bridge_domain *l2_bridge_domain_get(uint16_t domain_id);
struct l2_bridge_domain *l2_bridge_domain_create(const struct gr_l2_bridge_domain *config);
int l2_bridge_domain_destroy(uint16_t domain_id);
int l2_bridge_domain_update(const struct gr_l2_bridge_domain *config);

// MAC learning functions
int l2_mac_learn(uint16_t domain_id, const struct rte_ether_addr *mac, uint16_t iface_id, bool is_static);
int l2_mac_lookup(uint16_t domain_id, const struct rte_ether_addr *mac, uint16_t *iface_id);
int l2_mac_delete(uint16_t domain_id, const struct rte_ether_addr *mac);
int l2_mac_flush(uint16_t domain_id, uint16_t iface_id);
int l2_mac_age_out(uint16_t domain_id);

// Utility functions
uint32_t l2_get_timestamp(void);
int l2_validate_domain_id(uint16_t domain_id);

// MAC table statistics
struct l2_mac_stats {
	uint64_t entries;
	uint64_t lookups;
	uint64_t hits;
	uint64_t learns;
	uint64_t floods;
	uint64_t age_outs;
};

int l2_get_mac_stats(uint16_t domain_id, struct l2_mac_stats *stats);
