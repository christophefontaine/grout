// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static cmd_status_t phy_xconnect_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_iface_mode_req req;
	struct gr_iface iface, peer;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;

	if (iface_from_name(c, arg_str(p, "PEER"), &peer) < 0)
		return CMD_ERROR;

	req.mode = GR_IFACE_MODE_XCONNECT;
	req.iface_id = iface.id;
	req.domain_id = peer.id;

	if (gr_api_client_send_recv(c, GR_L2_MODE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t l3_mode_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_iface_mode_req req;
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;

	req.mode = GR_IFACE_MODE_L3;
	req.iface_id = iface.id;
	req.domain_id = 0;

	if (gr_api_client_send_recv(c, GR_L2_MODE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int iface_order(const void *ia, const void *ib) {
	const struct gr_iface *a = ia;
	const struct gr_iface *b = ib;
	return a->id - b->id;
}

static cmd_status_t mode_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	struct gr_infra_iface_list_req req = {
		.type = GR_IFACE_TYPE_PORT,
	};
	struct gr_infra_iface_list_resp *resp;
	struct gr_iface req_iface = {0};
	void *resp_ptr = NULL;

	iface_from_name(c, arg_str(p, "IFACE"), &req_iface);

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}
	resp = resp_ptr;
	qsort(resp->ifaces, resp->n_ifaces, sizeof(*resp->ifaces), iface_order);

	scols_table_new_column(table, "NAME", 0, 0);
	scols_table_new_column(table, "MODE", 0, 0);
	scols_table_new_column(table, "PEER", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_ifaces; i++) {
		const struct gr_iface *iface = &resp->ifaces[i];
		struct libscols_line *line = NULL;
		struct gr_iface peer;

		if (req_iface.id && req_iface.id != iface->id)
			continue;
		line = scols_table_new_line(table, NULL);
		scols_line_set_data(line, 0, iface->name);
		switch (iface->mode) {
		case GR_IFACE_MODE_L3:
			scols_line_set_data(line, 1, "L3");
			break;
		case GR_IFACE_MODE_XCONNECT:
			scols_line_set_data(line, 1, "XCONNECT");
			if (iface_from_id(c, iface->domain_id, &peer) < 0)
				scols_line_set_data(line, 2, "BROKEN");
			else
				scols_line_set_data(line, 2, peer.name);
			break;
		case GR_IFACE_MODE_COUNT:
			scols_line_set_data(line, 1, "UNKNOWN");
			break;
		}
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("interface", "Configure interface mode")),
		"mode l2 xconnect IFACE peer PEER",
		phy_xconnect_set,
		"Create a crossconnect from one interface to another",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help(
			"Interface name.",
			ec_node_dyn("PEER", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("interface", "Configure interface mode")),
		"mode l3 IFACE",
		l3_mode_set,
		"Reset interface to default (L3) mode",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("interface", "Show interface mode")),
		"mode [IFACE]",
		mode_show,
		"Show interface mode (l2/l3) configuration",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "interface mode",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
