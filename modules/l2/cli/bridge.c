// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the L2 API
#include "../api/gr_l2.h"

static cmd_status_t l2_bridge_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_bridge_add_req req = {0};
	const struct gr_l2_bridge_add_resp *resp;
	void *resp_ptr = NULL;

	// Parse bridge domain ID
	if (arg_u16(p, "DOMAIN_ID", &req.domain.domain_id) < 0) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	// Parse optional name
	const char *name = arg_str(p, "NAME");
	if (name != NULL) {
		strncpy(req.domain.name, name, sizeof(req.domain.name) - 1);
	} else {
		snprintf(req.domain.name, sizeof(req.domain.name), "bridge%u", req.domain.domain_id);
	}

	// Parse optional parameters
	if (arg_u16(p, "TIMEOUT", &req.domain.learning_timeout) < 0) {
		req.domain.learning_timeout = GR_L2_DEFAULT_LEARNING_TIMEOUT;
	}

	// Set default flooding behavior
	req.domain.flood_unknown = true;
	req.domain.flood_bcast = true;
	req.domain.flood_mcast = true;

	// Parse flood settings
	if (arg_str(p, "no-flood-unknown")) {
		req.domain.flood_unknown = false;
	}
	if (arg_str(p, "no-flood-broadcast")) {
		req.domain.flood_bcast = false;
	}
	if (arg_str(p, "no-flood-multicast")) {
		req.domain.flood_mcast = false;
	}

	if (gr_api_client_send_recv(c, GR_L2_BRIDGE_ADD, sizeof(req), &req, &resp_ptr) < 0) {
		return CMD_ERROR;
	}

	resp = resp_ptr;
	printf("Created bridge domain %u\n", resp->domain_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t l2_bridge_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_bridge_del_req req;

	if (arg_u16(p, "DOMAIN_ID", &req.domain_id) < 0) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_L2_BRIDGE_DEL, sizeof(req), &req, NULL) < 0) {
		return CMD_ERROR;
	}

	printf("Deleted bridge domain %u\n", req.domain_id);
	return CMD_SUCCESS;
}

// Forward declarations
static cmd_status_t l2_bridge_list(const struct gr_api_client *c, const struct ec_pnode *p);

static cmd_status_t l2_bridge_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	uint16_t domain_id;
	
	// Check if DOMAIN_ID was provided
	if (arg_u16(p, "DOMAIN_ID", &domain_id) == 0) {
		// Show specific bridge domain
		struct gr_l2_bridge_get_req req = {.domain_id = domain_id};
		const struct gr_l2_bridge_get_resp *resp;
		void *resp_ptr = NULL;

		if (gr_api_client_send_recv(c, GR_L2_BRIDGE_GET, sizeof(req), &req, &resp_ptr) < 0) {
			return CMD_ERROR;
		}

		resp = resp_ptr;
		if (resp == NULL) {
			printf("Bridge domain %u not found\n", domain_id);
			return CMD_ERROR;
		}
		
		printf("Bridge Domain %u:\n", resp->domain.domain_id);
		printf("  Name: %s\n", resp->domain.name);
		printf("  Learning timeout: %u seconds\n", resp->domain.learning_timeout);
		printf("  Flood unknown unicast: %s\n", resp->domain.flood_unknown ? "yes" : "no");
		printf("  Flood broadcast: %s\n", resp->domain.flood_bcast ? "yes" : "no");
		printf("  Flood multicast: %s\n", resp->domain.flood_mcast ? "yes" : "no");
		if (resp->domain.l3_iface_id != 0) {
			printf("  L3 interface: %u\n", resp->domain.l3_iface_id);
		}

		free(resp_ptr);
	} else {
		// No domain specified, show all domains (fallback to list)
		return l2_bridge_list(c, p);
	}
	
	return CMD_SUCCESS;
}

static cmd_status_t l2_bridge_list(const struct gr_api_client *c, const struct ec_pnode * /* p */) {
	const struct gr_l2_bridge_list_resp *resp;
	struct libscols_table *table;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_L2_BRIDGE_LIST, 0, NULL, &resp_ptr) < 0) {
		return CMD_ERROR;
	}

	resp = resp_ptr;

	table = scols_new_table();
	scols_table_new_column(table, "ID", 0, 0);
	scols_table_new_column(table, "NAME", 0, 0);
	scols_table_new_column(table, "TIMEOUT", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "FLOOD", 0, 0);
	scols_table_new_column(table, "L3_IFACE", 0, SCOLS_FL_RIGHT);

	for (uint16_t i = 0; i < resp->n_domains; i++) {
		const struct gr_l2_bridge_domain *domain = &resp->domains[i];
		struct libscols_line *line = scols_table_new_line(table, NULL);
		char flood_str[16];

		snprintf(flood_str, sizeof(flood_str), "%s%s%s",
			 domain->flood_unknown ? "U" : "",
			 domain->flood_bcast ? "B" : "",
			 domain->flood_mcast ? "M" : "");

		scols_line_sprintf(line, 0, "%u", domain->domain_id);
		scols_line_set_data(line, 1, domain->name);
		scols_line_sprintf(line, 2, "%u", domain->learning_timeout);
		scols_line_set_data(line, 3, flood_str);
		if (domain->l3_iface_id != 0) {
			scols_line_sprintf(line, 4, "%u", domain->l3_iface_id);
		} else {
			scols_line_set_data(line, 4, "-");
		}
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t l2_mac_flush(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mac_flush_req req = {0};

	if (arg_u16(p, "DOMAIN_ID", &req.domain_id) < 0) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	// Optional interface ID
	arg_u16(p, "IFACE_ID", &req.iface_id);

	if (gr_api_client_send_recv(c, GR_L2_MAC_FLUSH, sizeof(req), &req, NULL) < 0) {
		return CMD_ERROR;
	}

	if (req.iface_id != 0) {
		printf("Flushed MAC entries for interface %u in domain %u\n", 
		       req.iface_id, req.domain_id);
	} else {
		printf("Flushed all MAC entries in domain %u\n", req.domain_id);
	}
	return CMD_SUCCESS;
}

static cmd_status_t l2_mac_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mac_list_req req = {0};
	const struct gr_l2_mac_list_resp *resp;
	struct libscols_table *table;
	void *resp_ptr = NULL;

	if (arg_u16(p, "DOMAIN_ID", &req.domain_id) < 0) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_L2_MAC_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		return CMD_ERROR;
	}

	resp = resp_ptr;
	
	table = scols_new_table();
	scols_table_new_column(table, "MAC", 0, 0);
	scols_table_new_column(table, "IFACE", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TIMESTAMP", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "TYPE", 0, 0);

	for (uint16_t i = 0; i < resp->n_entries; i++) {
		const struct gr_l2_mac_entry *entry = &resp->entries[i];
		struct libscols_line *line = scols_table_new_line(table, NULL);

		scols_line_sprintf(line, 0, ETH_F, &entry->mac);
		scols_line_sprintf(line, 1, "%u", entry->iface_id);
		scols_line_sprintf(line, 2, "%u", entry->timestamp);
		scols_line_set_data(line, 3, entry->is_static ? "static" : "dynamic");
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);
	return CMD_SUCCESS;
}

// Define CLI context macros
#define L2_ADD_CTX(root) CLI_CONTEXT(root, CTX_ADD, CTX_ARG("l2", "Create L2 bridge elements."))
#define L2_DEL_CTX(root) CLI_CONTEXT(root, CTX_DEL, CTX_ARG("l2", "Delete L2 bridge elements."))
#define L2_SHOW_CTX(root) CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("l2", "Show L2 bridge details."))
#define L2_CLEAR_CTX(root) CLI_CONTEXT(root, CTX_CLEAR, CTX_ARG("l2", "Clear L2 bridge entries."))

static int ctx_init(struct ec_node *root) {
	int ret;

	// Bridge domain add command
	ret = CLI_COMMAND(
		L2_ADD_CTX(root),
		"bridge DOMAIN_ID [(name NAME),(timeout TIMEOUT),(no-flood-unknown),(no-flood-broadcast),(no-flood-multicast)]",
		l2_bridge_add,
		"Create a new bridge domain.",
		with_help("Bridge domain ID", ec_node_uint("DOMAIN_ID", 0, UINT16_MAX - 1, 10)),
		with_help("Bridge domain name", ec_node("any", "NAME")),
		with_help("MAC learning timeout (seconds)", ec_node_uint("TIMEOUT", 0, UINT16_MAX, 10)),
		with_help("Disable unknown unicast flooding", ec_node_str("no-flood-unknown", "no-flood-unknown")),
		with_help("Disable broadcast flooding", ec_node_str("no-flood-broadcast", "no-flood-broadcast")),
		with_help("Disable multicast flooding", ec_node_str("no-flood-multicast", "no-flood-multicast"))
	);
	if (ret < 0)
		return ret;

	// Bridge domain delete command
	ret = CLI_COMMAND(
		L2_DEL_CTX(root),
		"bridge DOMAIN_ID",
		l2_bridge_del,
		"Delete a bridge domain.",
		with_help("Bridge domain ID", ec_node_uint("DOMAIN_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	// Bridge domain show command
	ret = CLI_COMMAND(
		L2_SHOW_CTX(root),
		"bridge [DOMAIN_ID]",
		l2_bridge_show,
		"Show bridge domain details.",
		with_help("Bridge domain ID", ec_node_uint("DOMAIN_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	// Bridge domain list command (show all)
	ret = CLI_COMMAND(
		L2_SHOW_CTX(root),
		"bridge",
		l2_bridge_list,
		"List all bridge domains."
	);
	if (ret < 0)
		return ret;

	// MAC address show command  
	ret = CLI_COMMAND(
		L2_SHOW_CTX(root),
		"mac DOMAIN_ID",
		l2_mac_show,
		"Show MAC address table for bridge domain.",
		with_help("Bridge domain ID", ec_node_uint("DOMAIN_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	// MAC address flush command (clear)
	ret = CLI_COMMAND(
		L2_CLEAR_CTX(root),
		"mac DOMAIN_ID [(interface IFACE_ID)]",
		l2_mac_flush,
		"Flush MAC address table entries.",
		with_help("Bridge domain ID", ec_node_uint("DOMAIN_ID", 0, UINT16_MAX - 1, 10)),
		with_help("Interface ID", ec_node_uint("IFACE_ID", 1, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "l2 bridge",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
