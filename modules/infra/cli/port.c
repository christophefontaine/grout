// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "cli.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>
#include <gr_string.h>

#include <ecoli.h>

#include <errno.h>
#include <sys/queue.h>

static void port_show(struct gr_api_client *, const struct gr_iface *iface, struct gr_object *o) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;

	gr_object_field(o, "devargs", 0, "%s", port->devargs);
	gr_object_field(o, "driver", 0, "%s", port->driver_name);
	if (port->vdpa_driver[0] != '\0')
		gr_object_field(o, "vdpa", 0, "%s", port->vdpa_driver);
	gr_object_field(o, "mac", 0, ETH_F, &port->mac);
	gr_object_field(o, "n_rxq", GR_DISP_INT, "%u", port->n_rxq);
	gr_object_field(o, "n_txq", GR_DISP_INT, "%u", port->n_txq);
	gr_object_field(o, "rxq_size", GR_DISP_INT, "%u", port->rxq_size);
	gr_object_field(o, "txq_size", GR_DISP_INT, "%u", port->txq_size);
}

static void
port_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;
	snprintf(buf, len, "devargs=%s mac=" ETH_F, port->devargs, &port->mac);
}

static struct cli_iface_type port_type = {
	.type_id = GR_IFACE_TYPE_PORT,
	.show = port_show,
	.list_info = port_list_info,
};

static uint64_t parse_port_args(
	struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	struct gr_iface_info_port *port;
	const char *devargs;
	uint64_t set_attrs;

	set_attrs = parse_iface_args(c, p, iface, sizeof(*port), update);
	port = (struct gr_iface_info_port *)iface->info;
	devargs = arg_str(p, "DEVARGS");
	if (devargs != NULL) {
		if (gr_strcpy(port->devargs, sizeof(port->devargs), devargs) < 0)
			goto err;
	}
	if (arg_eth_addr(p, "MAC", &port->mac) == 0)
		set_attrs |= GR_PORT_SET_MAC;

	if (arg_u16(p, "N_RXQ", &port->n_rxq) == 0)
		set_attrs |= GR_PORT_SET_N_RXQS;

	if (arg_u16(p, "Q_SIZE", &port->rxq_size) == 0) {
		port->txq_size = port->rxq_size;
		set_attrs |= GR_PORT_SET_Q_SIZE;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
err:
	return 0;
}

// Send a filled-in interface-add request, report the created id and free the
// response. Shared by the "port" and "vduse" add commands.
static cmd_status_t
iface_add_send(struct gr_api_client *c, const struct gr_iface_add_req *req, size_t len) {
	const struct gr_iface_add_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_IFACE_ADD, len, req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t port_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_add_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_port);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	req->iface.type = GR_IFACE_TYPE_PORT;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_port_args(c, p, &req->iface, false) == 0)
		goto out;

	ret = iface_add_send(c, req, len);
out:
	free(req);
	return ret;
}

static cmd_status_t vduse_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_add_req *req = NULL;
	struct gr_iface_info_port *port;
	cmd_status_t ret = CMD_ERROR;
	const char *mode;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_port);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	req->iface.type = GR_IFACE_TYPE_PORT;
	req->iface.flags = GR_IFACE_F_UP;

	if (parse_iface_args(c, p, &req->iface, sizeof(*port), false) == 0)
		goto out;

	port = (struct gr_iface_info_port *)req->iface.info;

	// Number of virtio queue pairs (defaults to 1).
	port->n_rxq = 1;
	arg_u16(p, "N_RXQ", &port->n_rxq);

	if (arg_u16(p, "Q_SIZE", &port->rxq_size) == 0)
		port->txq_size = port->rxq_size;

	arg_eth_addr(p, "MAC", &port->mac);

	// Mark the port as VDUSE and select the vdpa attach mode (default: host).
	// The devargs is left empty on purpose: the control plane builds the
	// net_vhost string from the interface name, so the CLI never has to format
	// (and get wrong) DPDK device arguments.
	port->vduse_mode = GR_VDUSE_MODE_HOST;
	if ((mode = arg_str(p, "MODE")) != NULL && strcmp(mode, "vm") == 0)
		port->vduse_mode = GR_VDUSE_MODE_VM;

	ret = iface_add_send(c, req, len);
out:
	free(req);
	return ret;
}

static cmd_status_t port_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_set_req *req = NULL;
	cmd_status_t ret = CMD_ERROR;
	size_t len;

	len = sizeof(*req) + sizeof(struct gr_iface_info_port);
	if ((req = calloc(1, len)) == NULL)
		goto out;

	if ((req->set_attrs = parse_port_args(c, p, &req->iface, true)) == 0)
		goto out;

	if (gr_api_client_send_recv(c, GR_IFACE_SET, len, req, NULL) < 0)
		goto out;

	ret = CMD_SUCCESS;
out:
	free(req);
	return ret;
}

#define PORT_ATTRS_CMD IFACE_ATTRS_CMD ",(mac MAC),(rxqs N_RXQ),(qsize Q_SIZE)"

#define PORT_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS, with_help("Set the ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),  \
		with_help("Number of Rx queues.", ec_node_uint("N_RXQ", 0, UINT16_MAX - 1, 10)),   \
		with_help("Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"port NAME devargs DEVARGS [" PORT_ATTRS_CMD "]",
		port_add,
		"Create a new port.",
		with_help("Interface name.", ec_node("any", "NAME")),
		with_help("DPDK device args.", ec_node("devargs", "DEVARGS")),
		PORT_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"vduse NAME [(mode MODE),(queues N_RXQ),(qsize Q_SIZE),(mac MAC)," IFACE_ATTRS_CMD
		"]",
		vduse_add,
		"Create a VDUSE port (net_vhost backed by a vDPA device in userspace).",
		with_help(
			"Interface name (also used as the vDPA device name).",
			ec_node("any", "NAME")
		),
		with_help(
			"vDPA attach mode (default: host).",
			EC_NODE_OR(
				"MODE",
				with_help(
					"Expose a virtio-net netdev in the host kernel.",
					ec_node_str("", "host")
				),
				with_help(
					"Expose a vhost-vdpa device for a VM.",
					ec_node_str("", "vm")
				)
			)
		),
		with_help(
			"Number of virtio queue pairs.",
			ec_node_uint("N_RXQ", 1, UINT16_MAX - 1, 10)
		),
		with_help("Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10)),
		with_help("Set the ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
		IFACE_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"port NAME (name NEW_NAME)," PORT_ATTRS_CMD,
		port_set,
		"Modify port parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		PORT_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "infra port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&port_type);
}
