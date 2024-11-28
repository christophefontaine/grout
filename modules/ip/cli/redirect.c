// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip4.h>

static cmd_status_t redirect_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_redirect_all_req req;
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_IP4_REDIRECT_ALL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}


static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP_SET_CTX(root),
		"redirect iface IFACE",
		redirect_set,
		"Redirect all packets to the specified tun interface.",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;
	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipv4 redirect",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
