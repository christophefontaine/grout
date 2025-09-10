// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2_control.h"

#include <gr_log.h>

#include <errno.h>
#include <string.h>

#include <rte_hash.h>
#include <rte_malloc.h>

int l2_mac_learn(uint16_t domain_id, const struct rte_ether_addr *mac, uint16_t iface_id, bool is_static) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(domain_id);
	if (domain == NULL)
		return -1;
	
	if (mac == NULL || rte_is_zero_ether_addr(mac) || rte_is_broadcast_ether_addr(mac)) {
		errno = EINVAL;
		return -1;
	}
	
	struct l2_mac_key key = {
		.domain_id = domain_id,
	};
	memcpy(&key.mac, mac, sizeof(key.mac));
	
	rte_spinlock_lock(&domain->lock);
	
	// Check if entry already exists
	struct l2_mac_entry_internal *entry;
	void *entry_ptr;
	int ret = rte_hash_lookup_data(domain->mac_table, &key, &entry_ptr);
	entry = (struct l2_mac_entry_internal *)entry_ptr;
	
	if (ret >= 0) {
		// Update existing entry
		entry->iface_id = iface_id;
		entry->timestamp = l2_get_timestamp();
		entry->is_static = is_static;
		rte_spinlock_unlock(&domain->lock);
		return 0;
	}
	
	// Create new entry
	entry = rte_zmalloc(NULL, sizeof(*entry), 0);
	if (entry == NULL) {
		rte_spinlock_unlock(&domain->lock);
		errno = ENOMEM;
		return -1;
	}
	
	entry->iface_id = iface_id;
	entry->timestamp = l2_get_timestamp();
	entry->is_static = is_static;
	
	ret = rte_hash_add_key_data(domain->mac_table, &key, entry);
	if (ret < 0) {
		rte_free(entry);
		rte_spinlock_unlock(&domain->lock);
		errno = ENOSPC;
		return -1;
	}
	
	domain->n_entries++;
	rte_spinlock_unlock(&domain->lock);
	
	LOG(DEBUG, "Learned MAC %02x:%02x:%02x:%02x:%02x:%02x on interface %u in domain %u",
	    mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
	    mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5],
	    iface_id, domain_id);
	
	return 0;
}

int l2_mac_lookup(uint16_t domain_id, const struct rte_ether_addr *mac, uint16_t *iface_id) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(domain_id);
	if (domain == NULL || mac == NULL || iface_id == NULL)
		return -1;
	
	struct l2_mac_key key = {
		.domain_id = domain_id,
	};
	memcpy(&key.mac, mac, sizeof(key.mac));
	
	rte_spinlock_lock(&domain->lock);
	
	struct l2_mac_entry_internal *entry;
	void *entry_ptr;
	int ret = rte_hash_lookup_data(domain->mac_table, &key, &entry_ptr);
	entry = (struct l2_mac_entry_internal *)entry_ptr;
	
	if (ret < 0) {
		rte_spinlock_unlock(&domain->lock);
		errno = ENOENT;
		return -1;
	}
	
	// Check if entry has aged out
	uint32_t now = l2_get_timestamp();
	if (!entry->is_static && domain->learning_timeout > 0 && 
	    (now - entry->timestamp) > domain->learning_timeout) {
		// Entry has aged out, remove it
		rte_hash_del_key(domain->mac_table, &key);
		rte_free(entry);
		domain->n_entries--;
		rte_spinlock_unlock(&domain->lock);
		errno = ENOENT;
		return -1;
	}
	
	*iface_id = entry->iface_id;
	rte_spinlock_unlock(&domain->lock);
	
	return 0;
}

int l2_mac_delete(uint16_t domain_id, const struct rte_ether_addr *mac) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(domain_id);
	if (domain == NULL || mac == NULL)
		return -1;
	
	struct l2_mac_key key = {
		.domain_id = domain_id,
	};
	memcpy(&key.mac, mac, sizeof(key.mac));
	
	rte_spinlock_lock(&domain->lock);
	
	struct l2_mac_entry_internal *entry;
	void *entry_ptr;
	int ret = rte_hash_lookup_data(domain->mac_table, &key, &entry_ptr);
	entry = (struct l2_mac_entry_internal *)entry_ptr;
	
	if (ret < 0) {
		rte_spinlock_unlock(&domain->lock);
		errno = ENOENT;
		return -1;
	}
	
	rte_hash_del_key(domain->mac_table, &key);
	rte_free(entry);
	domain->n_entries--;
	rte_spinlock_unlock(&domain->lock);
	
	LOG(DEBUG, "Deleted MAC %02x:%02x:%02x:%02x:%02x:%02x from domain %u",
	    mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
	    mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5], domain_id);
	
	return 0;
}

int l2_mac_flush(uint16_t domain_id, uint16_t iface_id) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(domain_id);
	if (domain == NULL)
		return -1;
	
	rte_spinlock_lock(&domain->lock);
	
	const void *key;
	void *data;
	uint32_t iter = 0;
	int flushed = 0;
	
	// Iterate through all entries in the hash table
	while (rte_hash_iterate(domain->mac_table, &key, &data, &iter) >= 0) {
		struct l2_mac_entry_internal *entry = (struct l2_mac_entry_internal *)data;
		
		// Check if we should flush this entry
		bool should_flush = false;
		if (iface_id == 0) {
			// Flush all entries in the domain
			should_flush = true;
		} else if (entry->iface_id == iface_id) {
			// Flush entries for specific interface
			should_flush = true;
		}
		
		if (should_flush) {
			rte_hash_del_key(domain->mac_table, key);
			rte_free(entry);
			domain->n_entries--;
			flushed++;
		}
	}
	
	rte_spinlock_unlock(&domain->lock);
	
	LOG(INFO, "Flushed %d MAC entries from domain %u (iface %u)", 
	    flushed, domain_id, iface_id);
	
	return flushed;
}

int l2_mac_age_out(uint16_t domain_id) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(domain_id);
	if (domain == NULL)
		return -1;
	
	// Skip aging if timeout is disabled
	if (domain->learning_timeout == 0)
		return 0;
	
	uint32_t now = l2_get_timestamp();
	
	// Only age out entries every 60 seconds to avoid excessive overhead
	if ((now - domain->last_cleanup) < 60)
		return 0;
	
	rte_spinlock_lock(&domain->lock);
	
	const void *key;
	void *data;
	uint32_t iter = 0;
	int aged_out = 0;
	
	// Iterate through all entries in the hash table
	while (rte_hash_iterate(domain->mac_table, &key, &data, &iter) >= 0) {
		struct l2_mac_entry_internal *entry = (struct l2_mac_entry_internal *)data;
		
		// Check if entry has aged out
		if (!entry->is_static && (now - entry->timestamp) > domain->learning_timeout) {
			rte_hash_del_key(domain->mac_table, key);
			rte_free(entry);
			domain->n_entries--;
			aged_out++;
		}
	}
	
	domain->last_cleanup = now;
	rte_spinlock_unlock(&domain->lock);
	
	if (aged_out > 0) {
		LOG(DEBUG, "Aged out %d MAC entries from domain %u", aged_out, domain_id);
	}
	
	return aged_out;
}

int l2_get_mac_stats(uint16_t domain_id, struct l2_mac_stats *stats) {
	struct l2_bridge_domain *domain = l2_bridge_domain_get(domain_id);
	if (domain == NULL || stats == NULL)
		return -1;
	
	rte_spinlock_lock(&domain->lock);
	stats->entries = domain->n_entries;
	rte_spinlock_unlock(&domain->lock);
	
	// TODO: Add counters for lookups, hits, learns, floods, age_outs
	
	return 0;
}
