// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include "cli.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_net_types.h>
#include <gr_srv6.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>

static const char *format_sr6_flags(gr_sr6_flags_t flags) {
	static char buf[128]; // grcli is single threaded, this is safe
	size_t n = 0;
	buf[0] = 0;

	gr_flags_foreach (f, flags) {
		if (n > 0)
			SAFE_BUF(snprintf, sizeof(buf), " ");
		SAFE_BUF(snprintf, sizeof(buf), "%s", gr_sr6_flag_name(f));
	}
err:
	return buf;
}

static void sr6_show(struct gr_api_client *c, const struct gr_iface *iface, struct gr_object *o) {
	const struct gr_iface_info_sr6 *sr6 = (const struct gr_iface_info_sr6 *)iface->info;

	gr_object_field(o, "remote_sid", 0, IP6_F, &sr6->remote_sid);
	gr_object_field(o, "encap_vrf", 0, "%s", iface_name_from_id(c, sr6->encap_vrf_id));
	gr_object_field(o, "encap", 0, "%s", sr6->encap == SR_H_ENCAPS_RED ? "reduced" : "full");
	gr_object_field(o, "vlan", GR_DISP_INT, "%u", sr6->vlan_id);
	gr_object_field(o, "mac", 0, ETH_F, &sr6->mac);
	gr_object_field(o, "sr6_flags", GR_DISP_STR_ARRAY, "%s", format_sr6_flags(sr6->flags));
}

static void
sr6_list_info(struct gr_api_client *c, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_sr6 *sr6 = (const struct gr_iface_info_sr6 *)iface->info;

	snprintf(
		buf,
		len,
		"remote_sid=" IP6_F " encap_vrf=%s",
		&sr6->remote_sid,
		iface_name_from_id(c, sr6->encap_vrf_id)
	);
}

static struct cli_iface_type sr6_type = {
	.type_id = GR_IFACE_TYPE_SR6,
	.show = sr6_show,
	.list_info = sr6_list_info,
};

static uint64_t parse_sr6_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_sr6 *sr6;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*sr6), update);

	sr6 = (struct gr_iface_info_sr6 *)iface->info;

	if (arg_ip6(p, "SID", &sr6->remote_sid) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_SR6_SET_SID;
	}

	if (arg_str(p, "ENCAP_VRF") != NULL) {
		if (arg_vrf(c, p, "ENCAP_VRF", &sr6->encap_vrf_id) < 0)
			return 0;
		else
			set_attrs |= GR_SR6_SET_ENCAP_VRF;
	}

	if (arg_u16(p, "VLAN", &sr6->vlan_id) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_SR6_SET_VLAN;
	}

	if (arg_eth_addr(p, "MAC", &sr6->mac) < 0) {
		if (errno != ENOENT)
			return 0;
	} else {
		set_attrs |= GR_SR6_SET_MAC;
	}

	const char *encap = arg_str(p, "ENCAP");
	if (encap != NULL && strcmp(encap, "full") == 0) {
		sr6->encap = SR_H_ENCAPS;
		set_attrs |= GR_SR6_SET_ENCAP;
	} else if (encap != NULL && strcmp(encap, "reduced") == 0) {
		sr6->encap = SR_H_ENCAPS_RED;
		set_attrs |= GR_SR6_SET_ENCAP;
	}

	const char *on_off = arg_str(p, "FLOOD");
	if (on_off != NULL && strcmp(on_off, "on") == 0) {
		sr6->flags |= GR_SR6_F_FLOOD;
		set_attrs |= GR_SR6_SET_FLAGS;
	} else if (on_off != NULL && strcmp(on_off, "off") == 0) {
		sr6->flags &= ~GR_SR6_F_FLOOD;
		set_attrs |= GR_SR6_SET_FLAGS;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
}

static cmd_status_t sr6_add(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_iface_add_resp *resp;
	struct gr_iface_add_req *req = NULL;
	void *resp_ptr = NULL;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_sr6);
	if ((req = calloc(1, len)) == NULL)
		goto err;

	req->iface.type = GR_IFACE_TYPE_SR6;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_sr6_args(c, p, &req->iface, false) == 0)
		goto err;

	if (gr_api_client_send_recv(c, GR_IFACE_ADD, len, req, &resp_ptr) < 0)
		goto err;

	free(req);
	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
err:
	free(req);
	return CMD_ERROR;
}

static cmd_status_t sr6_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_sr6);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_sr6_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define SR6_ATTRS_CMD                                                                            \
	"(remote_sid SID),(encap_vrf ENCAP_VRF),(vlan VLAN),(mac MAC),"                          \
	"(encap ENCAP),(flood FLOOD)"

#define SR6_ATTRS_ARGS                                                                           \
	IFACE_ATTRS_ARGS,                                                                        \
		with_help("Remote SID for encapsulation (:: = disabled).", ec_node_re("SID", IPV6_RE)), \
		with_help(                                                                         \
			"L3 routing domain name for encap addresses.",                             \
			ec_node_dyn("ENCAP_VRF", complete_vrf_names, NULL)                         \
		),                                                                                 \
		with_help(                                                                         \
			"FDB vlan for decapsulated frames (0 = untagged).",                        \
			ec_node_uint("VLAN", 1, 4094, 10)                                          \
		),                                                                                 \
		with_help("Ethernet address (default random).", ec_node_re("MAC", ETH_ADDR_RE)),   \
		with_help(                                                                         \
			"Encapsulation mode.",                                                     \
			EC_NODE_OR(                                                                 \
				"ENCAP",                                                            \
				ec_node_str("", "full"),                                            \
				ec_node_str("", "reduced")                                          \
			)                                                                        \
		),                                                                                 \
		with_help(                                                                         \
			"Enable/disable bridge BUM flooding (default off).",                       \
			EC_NODE_OR("FLOOD", ec_node_str("", "on"), ec_node_str("", "off"))         \
		)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"sr6 NAME [" SR6_ATTRS_CMD "," IFACE_ATTRS_CMD "]",
		sr6_add,
		"Create a new SRv6 L2 service interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		SR6_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"sr6 NAME (name NEW_NAME)," SR6_ATTRS_CMD "," IFACE_ATTRS_CMD,
		sr6_set,
		"Modify SRv6 L2 service parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_SR6))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		SR6_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "sr6_iface",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_iface_type(&sr6_type);
	cli_context_register(&ctx);
}
