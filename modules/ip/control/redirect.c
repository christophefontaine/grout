// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip4_datapath.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_module.h>

static struct iface *tun_iface;

const struct iface *gr_get_tun_redirect(void) {
	return tun_iface;
}

static struct api_out redirect_all(const void *request, void ** /*response*/) {
	const struct gr_ip4_redirect_all_req *req = request;
	struct iface *iface;
	if((iface = iface_from_id(req->iface_id)) == NULL)
		return api_out(ENODEV, 0);

	if (iface->type_id != GR_IFACE_TYPE_TUN)
		return api_out(ENETUNREACH, 0);

	tun_iface = iface;
	return api_out(0, 0);
}

static struct gr_api_handler redirect_all_handler = {
	.name = "ipv4 redirect",
	.request_type = GR_IP4_REDIRECT_ALL,
	.callback = redirect_all,
};

static void iface_event_handler(iface_event_t event, struct iface *iface) {
	if (event == IFACE_EVENT_PRE_REMOVE && iface == tun_iface)
		tun_iface = NULL;
}

static struct iface_event_handler iface_event_address_handler = {
	.callback = iface_event_handler,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&redirect_all_handler);
	iface_event_register_handler(&iface_event_address_handler);
}
