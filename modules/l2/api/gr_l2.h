// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <stdint.h>
#include <sys/types.h>

#define GR_L2_MODULE 0xacdd

// L2 bridge domain configuration
struct gr_l2_bridge_domain {
	uint16_t domain_id;
	char name[64];
	uint16_t learning_timeout; // MAC learning timeout in seconds (0 = forever)
	bool flood_unknown; // Flood unknown unicast
	bool flood_bcast; // Flood broadcast
	bool flood_mcast; // Flood multicast
	uint16_t l3_iface_id; // L3 interface for this bridge domain (0 = none)
};

// MAC learning table entry
struct gr_l2_mac_entry {
	struct rte_ether_addr mac;
	uint16_t iface_id;
	uint16_t domain_id;
	uint32_t timestamp; // Last seen timestamp
	bool is_static; // Static entry (never ages out)
};

// L2 interface mode request
struct gr_l2_iface_mode_req {
	uint16_t iface_id;
	gr_iface_mode_t mode;
	uint16_t domain_id; // bridge domain ID for L2 mode
};

// L2 bridge domain APIs
#define GR_L2_BRIDGE_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0001)
struct gr_l2_bridge_add_req {
	struct gr_l2_bridge_domain domain;
};
struct gr_l2_bridge_add_resp {
	uint16_t domain_id;
};

#define GR_L2_BRIDGE_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0002)
struct gr_l2_bridge_del_req {
	uint16_t domain_id;
};

#define GR_L2_BRIDGE_SET REQUEST_TYPE(GR_L2_MODULE, 0x0003)
struct gr_l2_bridge_set_req {
	struct gr_l2_bridge_domain domain;
};

#define GR_L2_BRIDGE_GET REQUEST_TYPE(GR_L2_MODULE, 0x0004)
struct gr_l2_bridge_get_req {
	uint16_t domain_id;
};
struct gr_l2_bridge_get_resp {
	struct gr_l2_bridge_domain domain;
};

#define GR_L2_BRIDGE_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0005)
struct gr_l2_bridge_list_resp {
	uint16_t n_domains;
	struct gr_l2_bridge_domain domains[/* n_domains */];
};

// MAC table APIs
#define GR_L2_MAC_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0010)
struct gr_l2_mac_add_req {
	struct gr_l2_mac_entry entry;
};

#define GR_L2_MAC_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0011)
struct gr_l2_mac_del_req {
	struct rte_ether_addr mac;
	uint16_t domain_id;
};

#define GR_L2_MAC_GET REQUEST_TYPE(GR_L2_MODULE, 0x0012)
struct gr_l2_mac_get_req {
	struct rte_ether_addr mac;
	uint16_t domain_id;
};
struct gr_l2_mac_get_resp {
	struct gr_l2_mac_entry entry;
};

#define GR_L2_MAC_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0013)
struct gr_l2_mac_list_req {
	uint16_t domain_id; // 0 = all domains
};
struct gr_l2_mac_list_resp {
	uint16_t n_entries;
	struct gr_l2_mac_entry entries[/* n_entries */];
};

#define GR_L2_MAC_FLUSH REQUEST_TYPE(GR_L2_MODULE, 0x0014)
struct gr_l2_mac_flush_req {
	uint16_t domain_id; // 0 = all domains
	uint16_t iface_id; // 0 = all interfaces
};

// Interface mode API (already used in xconnect.c)
#define GR_L2_MODE_SET REQUEST_TYPE(GR_L2_MODULE, 0x0020)
// Uses gr_l2_iface_mode_req

// Maximum values
#define GR_L2_MAX_BRIDGE_DOMAINS 256
#define GR_L2_MAX_MAC_ENTRIES_PER_DOMAIN 4096
#define GR_L2_DEFAULT_LEARNING_TIMEOUT 300 // 5 minutes
