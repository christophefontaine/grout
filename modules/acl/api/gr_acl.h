// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#pragma once

#include <gr_api.h>
#include <gr_net_types.h>

#include <stdint.h>

#define GR_ACL_MODULE 0xa11c

// Match set types.
//
// A match set is a named container of match entries (see struct
// gr_acl_set_entry). The type selects which packet fields the entries of the
// set can match against.
//
// Mirrors FRR's enum ipset_type (lib/zclient.h): numeric values must stay in
// sync so that the grout-frr dataplane plugin can copy them as-is.
typedef enum : uint8_t {
	GR_ACL_SET_NET_NET = 1, // source and destination prefixes
	GR_ACL_SET_NET_PORT_NET, // source prefix + source port + destination prefix
	GR_ACL_SET_NET_PORT, // source prefix + source port
	GR_ACL_SET_NET, // source prefix only
} gr_acl_set_type_t;

// Convert match set type enum to string representation.
static inline const char *gr_acl_set_type_name(gr_acl_set_type_t type) {
	switch (type) {
	case GR_ACL_SET_NET_NET:
		return "net-net";
	case GR_ACL_SET_NET_PORT_NET:
		return "net-port-net";
	case GR_ACL_SET_NET_PORT:
		return "net-port";
	case GR_ACL_SET_NET:
		return "net";
	}
	return "?";
}

// IP network with address family, used in match set entries.
// GR_AF_UNSPEC family or a zero prefix length means wildcard.
struct gr_acl_net {
	addr_family_t af;
	uint8_t prefixlen;
	union {
		ip4_addr_t ip4;
		struct rte_ipv6_addr ip6;
	};
};

// Named set of match entries, scoped to a VRF and an address family.
// Mirrors FRR's struct zebra_pbr_ipset.
struct gr_acl_set {
	uint32_t set_id; // User assigned, 0 = auto allocate.
	uint16_t vrf_id;
	addr_family_t af;
	gr_acl_set_type_t type;
};

// Entry of a match set. Fields set to zero are wildcards.
// For ICMP (proto 1/58), src_port_min is the ICMP type and dst_port_min the
// ICMP code. Mirrors FRR's struct zebra_pbr_ipset_entry.
struct gr_acl_set_entry {
	uint32_t set_id;
	uint32_t entry_id; // User assigned, 0 = auto allocate.
	struct gr_acl_net src;
	struct gr_acl_net dst;
	uint16_t src_port_min;
	uint16_t src_port_max;
	uint16_t dst_port_min;
	uint16_t dst_port_max;
	uint8_t proto; // IP protocol number, 0 = any.
};

// Filter match flags.
//
// Describe how the filter combines the entries of its referenced match set
// with the filter level matches carried by struct gr_acl_filter.
//
// Mirrors FRR's MATCH_*_SET defines (lib/pbr.h): bit values must stay in sync
// so that the grout-frr dataplane plugin can copy them as-is.
#define GR_ACL_MATCH_IP_SRC (1 << 0) // Set applies to source IP.
#define GR_ACL_MATCH_IP_DST (1 << 1) // Set applies to destination IP.
#define GR_ACL_MATCH_PORT_SRC (1 << 2) // Match source port.
#define GR_ACL_MATCH_PORT_DST (1 << 3) // Match destination port.
#define GR_ACL_MATCH_PORT_SRC_RANGE (1 << 4) // Match source port range.
#define GR_ACL_MATCH_PORT_DST_RANGE (1 << 5) // Match destination port range.
#define GR_ACL_MATCH_DSCP (1 << 6) // Match DSCP.
#define GR_ACL_MATCH_DSCP_INVERSE (1 << 7) // Invert DSCP match.
#define GR_ACL_MATCH_PKT_LEN_INVERSE (1 << 8) // Invert packet length match.
#define GR_ACL_MATCH_FRAGMENT_INVERSE (1 << 9) // Invert fragment match.
#define GR_ACL_MATCH_ICMP (1 << 10) // Match ICMP type/code.
#define GR_ACL_MATCH_PROTOCOL (1 << 11) // Match IP protocol.
#define GR_ACL_MATCH_FLOW_LABEL (1 << 12) // Match IPv6 flow label.
#define GR_ACL_MATCH_FLOW_LABEL_INVERSE (1 << 13) // Invert flow label match.

#define GR_ACL_MATCH_VALID                                                                         \
	(GR_ACL_MATCH_IP_SRC | GR_ACL_MATCH_IP_DST | GR_ACL_MATCH_PORT_SRC | GR_ACL_MATCH_PORT_DST \
	 | GR_ACL_MATCH_PORT_SRC_RANGE | GR_ACL_MATCH_PORT_DST_RANGE | GR_ACL_MATCH_DSCP           \
	 | GR_ACL_MATCH_DSCP_INVERSE | GR_ACL_MATCH_PKT_LEN_INVERSE                                \
	 | GR_ACL_MATCH_FRAGMENT_INVERSE | GR_ACL_MATCH_ICMP | GR_ACL_MATCH_PROTOCOL               \
	 | GR_ACL_MATCH_FLOW_LABEL | GR_ACL_MATCH_FLOW_LABEL_INVERSE)

// Filter actions. Semantically mirrors FRR's ZEBRA_IPTABLES_DROP/FORWARD
// (values intentionally differ: the grout default is drop).
typedef enum : uint8_t {
	GR_ACL_ACTION_DROP = 0, // Discard matching packets.
	GR_ACL_ACTION_MARK = 1, // Forward matching packets with fwmark set.
} gr_acl_action_t;

// Convert filter action enum to string representation.
static inline const char *gr_acl_action_name(gr_acl_action_t action) {
	switch (action) {
	case GR_ACL_ACTION_DROP:
		return "drop";
	case GR_ACL_ACTION_MARK:
		return "mark";
	}
	return "?";
}

// Filter applied on a list of interfaces.
//
// Combines a referenced match set (set_id) with filter level matches and an
// action. A packet matches the filter when it matches at least one entry of
// the set (as selected by GR_ACL_MATCH_IP_SRC/IP_DST) and the filter level
// matches. Mirrors FRR's struct zebra_pbr_iptable.
struct gr_acl_filter {
	uint32_t filter_id; // User assigned, 0 = auto allocate.
	uint16_t vrf_id;
	uint32_t set_id; // Referenced match set.
	uint32_t match_bm; // GR_ACL_MATCH_* flags.
	gr_acl_action_t action;
	uint32_t fwmark; // Mark set on matching packets (GR_ACL_ACTION_MARK).
	uint16_t pkt_len_min; // Packet length range.
	uint16_t pkt_len_max;
	uint16_t tcp_flags; // TCP flags to match (byte 13 of the TCP header).
	uint16_t tcp_mask; // TCP flags mask.
	uint8_t dscp; // DSCP value to match.
	uint8_t fragment; // Fragment flags (FRR FRAGMENT_*).
	uint8_t proto; // IP protocol to match.
	uint16_t flow_label; // IPv6 flow label.
	addr_family_t af;
	uint64_t pkts; // Read only: number of packets matched.
	uint16_t n_ifaces; // Number of interfaces the filter applies on.
	uint16_t iface_ids[]; // Interface ids, n_ifaces of them.
};

enum gr_acl_requests : uint32_t {
	GR_ACL_SET_ADD = GR_MSG_TYPE(GR_ACL_MODULE, 0x0001),
	GR_ACL_SET_DEL,
	GR_ACL_SET_LIST,
	GR_ACL_ENTRY_ADD,
	GR_ACL_ENTRY_DEL,
	GR_ACL_ENTRY_LIST,
	GR_ACL_FILTER_ADD,
	GR_ACL_FILTER_DEL,
	GR_ACL_FILTER_LIST,
};

// match sets //////////////////////////////////////////////////////////////////

// Add a new match set.
struct gr_acl_set_add_req {
	uint8_t exist_ok; // If true, update existing set instead of returning EEXIST.
	struct gr_acl_set set;
};

GR_REQ(GR_ACL_SET_ADD, struct gr_acl_set_add_req, struct gr_empty);

// Delete a match set. Deleting a set referenced by filters fails with EBUSY.
struct gr_acl_set_del_req {
	uint32_t set_id;
	uint8_t missing_ok; // If true, ignore ENOENT.
};

GR_REQ(GR_ACL_SET_DEL, struct gr_acl_set_del_req, struct gr_empty);

// List match sets.
struct gr_acl_set_list_req {
	uint16_t vrf_id; // GR_VRF_ID_UNDEF for all.
};

GR_REQ_STREAM(GR_ACL_SET_LIST, struct gr_acl_set_list_req, struct gr_acl_set);

// match set entries ///////////////////////////////////////////////////////////

// Add a new entry to a match set.
struct gr_acl_entry_add_req {
	uint8_t exist_ok; // If true, update existing entry instead of returning EEXIST.
	struct gr_acl_set_entry entry;
};

GR_REQ(GR_ACL_ENTRY_ADD, struct gr_acl_entry_add_req, struct gr_empty);

// Delete an entry from a match set.
struct gr_acl_entry_del_req {
	uint32_t set_id;
	uint32_t entry_id;
	uint8_t missing_ok; // If true, ignore ENOENT.
};

GR_REQ(GR_ACL_ENTRY_DEL, struct gr_acl_entry_del_req, struct gr_empty);

// List the entries of a match set.
struct gr_acl_entry_list_req {
	uint32_t set_id;
};

GR_REQ_STREAM(GR_ACL_ENTRY_LIST, struct gr_acl_entry_list_req, struct gr_acl_set_entry);

// filters /////////////////////////////////////////////////////////////////////

// Add a new filter. The request payload holds n_ifaces interface ids after
// the struct gr_acl_filter.
struct gr_acl_filter_add_req {
	uint8_t exist_ok; // If true, update existing filter instead of returning EEXIST.
	struct gr_acl_filter filter;
};

GR_REQ(GR_ACL_FILTER_ADD, struct gr_acl_filter_add_req, struct gr_empty);

// Delete a filter.
struct gr_acl_filter_del_req {
	uint32_t filter_id;
	uint8_t missing_ok; // If true, ignore ENOENT.
};

GR_REQ(GR_ACL_FILTER_DEL, struct gr_acl_filter_del_req, struct gr_empty);

// List filters. Each streamed filter is followed by its n_ifaces interface
// ids in the response payload.
struct gr_acl_filter_list_req {
	uint16_t vrf_id; // GR_VRF_ID_UNDEF for all.
};

GR_REQ_STREAM(GR_ACL_FILTER_LIST, struct gr_acl_filter_list_req, struct gr_acl_filter);

// events //////////////////////////////////////////////////////////////////////

enum gr_acl_events : uint32_t {
	GR_EVENT_ACL_SET_ADD = GR_MSG_TYPE(GR_ACL_MODULE, 0x1001),
	GR_EVENT_ACL_SET_DEL,
	GR_EVENT_ACL_ENTRY_ADD,
	GR_EVENT_ACL_ENTRY_DEL,
	GR_EVENT_ACL_FILTER_ADD,
	GR_EVENT_ACL_FILTER_DEL,
};

GR_EVENT(GR_EVENT_ACL_SET_ADD, struct gr_acl_set);
GR_EVENT(GR_EVENT_ACL_SET_DEL, struct gr_acl_set);
GR_EVENT(GR_EVENT_ACL_ENTRY_ADD, struct gr_acl_set_entry);
GR_EVENT(GR_EVENT_ACL_ENTRY_DEL, struct gr_acl_set_entry);
GR_EVENT(GR_EVENT_ACL_FILTER_ADD, struct gr_acl_filter);
GR_EVENT(GR_EVENT_ACL_FILTER_DEL, struct gr_acl_filter);
