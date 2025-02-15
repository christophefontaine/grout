// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_vxlan.h"
#include "vxlan_priv.h"

#include <gr_event.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_port.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>

#include <string.h>

static void vxlan_to_api(void *info, const struct iface *iface) {
	const struct iface_info_vxlan *vxlan = (const struct iface_info_vxlan *)iface->info;
	struct gr_iface_info_vxlan *api = info;
	memcpy(api, iface->info, sizeof(*vxlan));
}

static int iface_vxlan_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	gr_iface_flags_t flags,
	uint16_t mtu,
	uint16_t vrf_id,
	const void *api_info
) {
	gr_event_push(IFACE_EVENT_POST_RECONFIG, iface);
	return 0;
}

static int iface_vxlan_fini(struct iface *iface) {
	struct iface_info_ipip *ipip = (struct iface_info_ipip *)iface->info;
	struct ipip_key key = {ipip->local, ipip->remote, iface->vrf_id};

	rte_hash_del_key(ipip_hash, &key);

	return 0;
}

static int iface_vxlan_init(struct iface *iface, const void *api_info) {
	int ret;

	ret = iface_vxlan_reconfig(
		iface, IFACE_SET_ALL, iface->flags, iface->mtu, iface->vrf_id, api_info
	);
	if (ret < 0) {
		iface_vxlan_fini(iface);
		errno = -ret;
	}

	return ret;
}

static struct iface_type iface_type_vxlan = {
	.id = GR_IFACE_TYPE_VXLAN,
	.name = "vxlan",
	.info_size = sizeof(struct iface_info_vxlan),
	.init = iface_vxlan_init,
	.reconfig = iface_vxlan_reconfig,
	.fini = iface_vxlan_fini,
	.to_api = vxlan_to_api,
};

static void vxlan_init(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "vxlan",
		.entries = MAX_IFACES,
		.key_len = sizeof(struct vxlan_key),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	vxlan_hash = rte_hash_create(&params);
	if (vxlan_hash == NULL)
		ABORT("rte_hash_create(vxlan)");
}

static void vxlan_fini(struct event_base *) {
	rte_hash_free(vxlan_hash);
	vxlan_hash = NULL;
}

static struct gr_module vxlan_module = {
	.name = "vxlan",
	.init = vxlan_init,
	.fini = vxlan_fini,
	.fini_prio = 1000,
};

RTE_INIT(vxlan_constructor) {
	gr_register_module(&vxlan_module);
	iface_type_register(&iface_type_vxlan);
}
