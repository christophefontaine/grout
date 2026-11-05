// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#include "cli.h"
#include "cli_event.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_acl.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static int arg_acl_set_type(const struct ec_pnode *p, gr_acl_set_type_t *type) {
	const char *s = arg_str(p, "TYPE");

	if (s == NULL)
		return errno_set(EINVAL);
	if (strcmp(s, "net-net") == 0)
		*type = GR_ACL_SET_NET_NET;
	else if (strcmp(s, "net-port-net") == 0)
		*type = GR_ACL_SET_NET_PORT_NET;
	else if (strcmp(s, "net-port") == 0)
		*type = GR_ACL_SET_NET_PORT;
	else if (strcmp(s, "net") == 0)
		*type = GR_ACL_SET_NET;
	else
		return errno_set(EINVAL);
	return 0;
}

// Parse a family agnostic prefix into a gr_acl_net. An absent argument is
// a wildcard.
static int arg_acl_net(const struct ec_pnode *p, const char *id, struct gr_acl_net *net) {
	const char *s = arg_str(p, id);
	struct ip4_net v4;
	struct ip6_net v6;

	memset(net, 0, sizeof(*net));
	if (s == NULL)
		return 0;
	if (ip4_net_parse(s, &v4, true) == 0) {
		net->af = GR_AF_IP4;
		net->prefixlen = v4.prefixlen;
		net->ip4 = v4.ip;
	} else if (ip6_net_parse(s, &v6, true) == 0) {
		net->af = GR_AF_IP6;
		net->prefixlen = v6.prefixlen;
		net->ip6 = v6.ip;
	} else {
		return errno_set(EINVAL);
	}
	return 0;
}

// Parse "N" or "LO:HI" into a min/max range. An absent argument leaves
// both bounds at zero (wildcard). The values must not exceed limit and
// the range must not be empty.
static int arg_acl_ports(
	const struct ec_pnode *p,
	const char *id,
	uint32_t limit,
	uint16_t *lo,
	uint16_t *hi
) {
	const char *s = arg_str(p, id);
	unsigned long v_lo, v_hi = 0;

	*lo = 0;
	*hi = 0;
	if (s == NULL)
		return 0;
	if (sscanf(s, "%lu:%lu", &v_lo, &v_hi) == 2) {
		if (v_lo > v_hi)
			return errno_set(EINVAL);
	} else if (sscanf(s, "%lu", &v_lo) == 1) {
		v_hi = 0; // single value, exact match
	} else {
		return errno_set(EINVAL);
	}
	if (v_lo > limit || v_hi > limit)
		return errno_set(EINVAL);
	*lo = v_lo;
	*hi = v_hi;
	return 0;
}

static cmd_status_t acl_set_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_acl_set_add_req req = {.exist_ok = true};

	if (arg_u32(p, "SET", &req.set.set_id) < 0)
		return CMD_ERROR;
	if (arg_str(p, "ipv4") != NULL)
		req.set.af = GR_AF_IP4;
	else
		req.set.af = GR_AF_IP6;
	if (arg_acl_set_type(p, &req.set.type) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_ACL_SET_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t acl_set_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_acl_set_del_req req = {.missing_ok = true};

	if (arg_u32(p, "SET", &req.set_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_ACL_SET_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t acl_set_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_acl_set_list_req req = {.vrf_id = GR_VRF_ID_UNDEF};
	const struct gr_acl_set *set;
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "SET", GR_DISP_RIGHT | GR_DISP_INT); // 0
	gr_table_column(table, "VRF", GR_DISP_LEFT); // 1
	gr_table_column(table, "FAMILY", GR_DISP_LEFT); // 2
	gr_table_column(table, "TYPE", GR_DISP_LEFT); // 3
	gr_table_column(table, "ENTRIES", GR_DISP_RIGHT | GR_DISP_INT); // 4

	gr_api_client_stream_foreach (set, ret, c, GR_ACL_SET_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%u", set->set_id);
		gr_table_cell(table, 1, "%s", iface_name_from_id(c, set->vrf_id));
		gr_table_cell(table, 2, "%s", gr_af_name(set->af));
		gr_table_cell(table, 3, "%s", gr_acl_set_type_name(set->type));
		gr_table_cell(table, 4, "-");

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t acl_entry_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_acl_entry_add_req req = {.exist_ok = true};

	if (arg_u32(p, "SET", &req.entry.set_id) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "ENTRY", &req.entry.entry_id) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_acl_net(p, "SRC", &req.entry.src) < 0)
		return CMD_ERROR;
	if (arg_acl_net(p, "DST", &req.entry.dst) < 0)
		return CMD_ERROR;
	if (arg_acl_ports(p, "SPORT", UINT16_MAX, &req.entry.src_port_min, &req.entry.src_port_max) < 0)
		return CMD_ERROR;
	if (arg_acl_ports(p, "DPORT", UINT16_MAX, &req.entry.dst_port_min, &req.entry.dst_port_max) < 0)
		return CMD_ERROR;
	if (arg_u8(p, "PROTO", &req.entry.proto) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_ACL_ENTRY_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t acl_entry_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_acl_entry_del_req req = {.missing_ok = true};

	if (arg_u32(p, "SET", &req.set_id) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "ENTRY", &req.entry_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_ACL_ENTRY_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static void acl_net_format(const struct gr_acl_net *net, char *buf, size_t len) {
	char addr[INET6_ADDRSTRLEN];

	if (net->af == GR_AF_IP4)
		inet_ntop(AF_INET, &net->ip4, addr, sizeof(addr));
	else
		inet_ntop(AF_INET6, &net->ip6, addr, sizeof(addr));
	snprintf(buf, len, "%s/%u", addr, net->prefixlen);
}

static cmd_status_t acl_entry_show(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_acl_set_entry *entry;
	struct gr_acl_entry_list_req req;
	char src[64], dst[64];
	int ret;

	if (arg_u32(p, "SET", &req.set_id) < 0)
		return CMD_ERROR;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "SET", GR_DISP_RIGHT | GR_DISP_INT); // 0
	gr_table_column(table, "ENTRY", GR_DISP_RIGHT | GR_DISP_INT); // 1
	gr_table_column(table, "SRC", GR_DISP_LEFT); // 2
	gr_table_column(table, "DST", GR_DISP_LEFT); // 3
	gr_table_column(table, "SPORT", GR_DISP_LEFT); // 4
	gr_table_column(table, "DPORT", GR_DISP_LEFT); // 5
	gr_table_column(table, "PROTO", GR_DISP_RIGHT | GR_DISP_INT); // 6

	gr_api_client_stream_foreach (entry, ret, c, GR_ACL_ENTRY_LIST, sizeof(req), &req) {
		acl_net_format(&entry->src, src, sizeof(src));
		acl_net_format(&entry->dst, dst, sizeof(dst));

		gr_table_cell(table, 0, "%u", entry->set_id);
		gr_table_cell(table, 1, "%u", entry->entry_id);
		gr_table_cell(table, 2, "%s", src);
		gr_table_cell(table, 3, "%s", dst);
		if (entry->src_port_min != 0) {
			if (entry->src_port_max != 0)
				gr_table_cell(
					table, 4, "%u-%u", entry->src_port_min, entry->src_port_max
				);
			else
				gr_table_cell(table, 4, "%u", entry->src_port_min);
		}
		if (entry->dst_port_min != 0) {
			if (entry->dst_port_max != 0)
				gr_table_cell(
					table, 5, "%u-%u", entry->dst_port_min, entry->dst_port_max
				);
			else
				gr_table_cell(table, 5, "%u", entry->dst_port_min);
		}
		if (entry->proto != 0)
			gr_table_cell(table, 6, "%u", entry->proto);

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t acl_filter_add(struct gr_api_client *c, const struct ec_pnode *p) {
	// Heap allocated: the flexible array iface_ids[] extends past the
	// struct, a stack allocation would overflow.
	struct gr_acl_filter_add_req *req = calloc(1, sizeof(*req) + sizeof(uint16_t));
	uint16_t lo, hi;
	cmd_status_t ret = CMD_ERROR;

	if (req == NULL)
		return CMD_ERROR;
	req->exist_ok = true;

	if (arg_u32(p, "FILTER", &req->filter.filter_id) < 0)
		goto err;
	if (arg_u32(p, "SET", &req->filter.set_id) < 0)
		goto err;
	req->filter.action = GR_ACL_ACTION_DROP;
	if (arg_str(p, "ipv4") != NULL)
		req->filter.af = GR_AF_IP4;
	else
		req->filter.af = GR_AF_IP6;
	if (arg_str(p, "IFACE") != NULL) {
		if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req->filter.iface_ids[0]) < 0)
			goto err;
		req->filter.n_ifaces = 1;
	}
	// The dscp and proto criteria are only applied by the control plane
	// when their match flag is set.
	if (arg_str(p, "DSCP") != NULL) {
		req->filter.match_bm |= GR_ACL_MATCH_DSCP;
		if (arg_u8(p, "DSCP", &req->filter.dscp) < 0)
			goto err;
	}
	if (arg_str(p, "PROTO") != NULL) {
		req->filter.match_bm |= GR_ACL_MATCH_PROTOCOL;
		if (arg_u8(p, "PROTO", &req->filter.proto) < 0)
			goto err;
	}
	if (arg_acl_ports(p, "PKTLEN", UINT16_MAX, &lo, &hi) < 0)
		goto err;
	// a bare length means an exact match, not an open ended range
	req->filter.pkt_len_min = lo;
	req->filter.pkt_len_max = hi != 0 ? hi : lo;
	if (arg_str(p, "TCPFLAGS") != NULL) {
		if (arg_acl_ports(p, "TCPFLAGS", UINT8_MAX, &lo, &hi) < 0)
			goto err;
		req->filter.tcp_flags = lo;
		// a bare value means an exact match on the flags byte
		req->filter.tcp_mask = hi != 0 ? hi : 0xff;
	}

	if (gr_api_client_send_recv(c, GR_ACL_FILTER_ADD, sizeof(*req) + sizeof(uint16_t), req, NULL)
	    < 0)
		goto err;

	ret = CMD_SUCCESS;
err:
	free(req);
	return ret;
}

static cmd_status_t acl_filter_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_acl_filter_del_req req = {.missing_ok = true};

	if (arg_u32(p, "FILTER", &req.filter_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_ACL_FILTER_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t acl_filter_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_acl_filter_list_req req = {.vrf_id = GR_VRF_ID_UNDEF};
	const struct gr_acl_filter *filter;
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "FILTER", GR_DISP_RIGHT | GR_DISP_INT); // 0
	gr_table_column(table, "SET", GR_DISP_RIGHT | GR_DISP_INT); // 1
	gr_table_column(table, "ACTION", GR_DISP_LEFT); // 2
	gr_table_column(table, "IFACES", GR_DISP_LEFT); // 3
	gr_table_column(table, "PKTS", GR_DISP_RIGHT | GR_DISP_INT); // 4

	gr_api_client_stream_foreach (filter, ret, c, GR_ACL_FILTER_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%u", filter->filter_id);
		gr_table_cell(table, 1, "%u", filter->set_id);
		gr_table_cell(table, 2, "%s", gr_acl_action_name(filter->action));
		for (uint16_t i = 0; i < filter->n_ifaces; i++)
			gr_table_cell(table, 3, "%s", iface_name_from_id(c, filter->iface_ids[i]));
		gr_table_cell(table, 4, "%" PRIu64, filter->pkts);

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define ACL_CTX(root) CLI_CONTEXT(root, CTX_ARG("acl", "Access control lists."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"set add SET family (ipv4),(ipv6) type TYPE",
		acl_set_add,
		"Add an ACL match set.",
		with_help("Match set id.", ec_node_uint("SET", 1, UINT32_MAX, 10)),
		with_help("IPv4 address family.", ec_node_str("ipv4", "ipv4")),
		with_help("IPv6 address family.", ec_node_str("ipv6", "ipv6")),
		with_help(
			"Match set type (net, net-net, net-port, net-port-net).",
			ec_node_re("TYPE", "^(net|net-net|net-port|net-port-net)$")
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"set del SET",
		acl_set_del,
		"Delete an ACL match set.",
		with_help("Match set id.", ec_node_uint("SET", 1, UINT32_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(ACL_CTX(root), "set [show]", acl_set_show, "Show the ACL match sets.");
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"entry add SET [ENTRY] [src SRC] [dst DST] [sport SPORT] [dport DPORT] "
		"[proto PROTO]",
		acl_entry_add,
		"Add an entry to an ACL match set.",
		with_help("Match set id.", ec_node_uint("SET", 1, UINT32_MAX, 10)),
		with_help(
			"Entry id (auto allocated if not set).",
			ec_node_uint("ENTRY", 1, UINT32_MAX, 10)
		),
		with_help("Source prefix.", ec_node_re("SRC", IP_ANY_NET_RE)),
		with_help("Destination prefix.", ec_node_re("DST", IP_ANY_NET_RE)),
		with_help(
			"Source port or port range.", ec_node_re("SPORT", "^([0-9]+)(:[0-9]+)?$")
		),
		with_help(
			"Destination port or port range.",
			ec_node_re("DPORT", "^([0-9]+)(:[0-9]+)?$")
		),
		with_help("IP protocol number.", ec_node_uint("PROTO", 0, 255, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"entry del SET ENTRY",
		acl_entry_del,
		"Delete an entry from an ACL match set.",
		with_help("Match set id.", ec_node_uint("SET", 1, UINT32_MAX, 10)),
		with_help("Entry id.", ec_node_uint("ENTRY", 1, UINT32_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"entry [show] set SET",
		acl_entry_show,
		"Show the entries of an ACL match set.",
		with_help("Match set id.", ec_node_uint("SET", 1, UINT32_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"filter add FILTER set SET family (ipv4),(ipv6) action drop"
		" [iface IFACE] [dscp DSCP] [proto PROTO] [pkt-len PKTLEN] [tcp-flags TCPFLAGS]",
		acl_filter_add,
		"Add an ACL filter.",
		with_help("Filter id.", ec_node_uint("FILTER", 1, UINT32_MAX, 10)),
		with_help("Match set id.", ec_node_uint("SET", 1, UINT32_MAX, 10)),
		with_help("IPv4 address family.", ec_node_str("ipv4", "ipv4")),
		with_help("IPv6 address family.", ec_node_str("ipv6", "ipv6")),
		with_help("Drop matching packets.", ec_node_str("drop", "drop")),
		with_help(
			"Interface the filter applies on.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("DSCP value to match.", ec_node_uint("DSCP", 0, 63, 10)),
		with_help("IP protocol number to match.", ec_node_uint("PROTO", 0, 255, 10)),
		with_help(
			"Packet length or length range (a bare length is an exact match).",
			ec_node_re("PKTLEN", "^([0-9]+)(:[0-9]+)?$")
		),
		with_help(
			"TCP flags value or value:mask (a bare value matches the flags byte exactly).",
			ec_node_re("TCPFLAGS", "^([0-9]+)(:[0-9]+)?$")
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ACL_CTX(root),
		"filter del FILTER",
		acl_filter_del,
		"Delete an ACL filter.",
		with_help("Filter id.", ec_node_uint("FILTER", 1, UINT32_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(ACL_CTX(root), "filter [show]", acl_filter_show, "Show the ACL filters.");

	return ret;
}

static struct cli_context ctx = {
	.name = "acl",
	.init = ctx_init,
};

static void acl_event_print(uint32_t event, const void *obj) {
	const struct gr_acl_filter *filter = obj;

	switch (event) {
	case GR_EVENT_ACL_FILTER_ADD:
		printf("acl filter %u added: set %u action %s\n",
		       filter->filter_id,
		       filter->set_id,
		       gr_acl_action_name(filter->action));
		break;
	case GR_EVENT_ACL_FILTER_DEL:
		printf("acl filter %u deleted\n", filter->filter_id);
		break;
	default:
		break;
	}
}

static struct cli_event_printer printer = {
	.name = "acl",
	.print = acl_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_ACL_FILTER_ADD,
		GR_EVENT_ACL_FILTER_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
