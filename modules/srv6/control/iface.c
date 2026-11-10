// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include "iface.h"
#include "log.h"
#include "srv6.h"
#include "vrf.h"

#include <gr_infra.h>
#include <gr_srv6.h>

#include <rte_ethdev.h>
#include <rte_ether.h>

LOG_TYPE("srv6");

static int iface_sr6_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
) {
	const struct gr_iface_info_sr6 *next = api_info;
	struct iface_info_sr6 *cur = iface_info_sr6(iface);
	uint16_t old_encap_vrf = cur->encap_vrf_id;
	uint16_t new_encap_vrf = old_encap_vrf;

	if (set_attrs & GR_SR6_SET_ENCAP_VRF) {
		new_encap_vrf = next->encap_vrf_id;
		if (new_encap_vrf == GR_VRF_ID_UNDEF)
			new_encap_vrf = vrf_default_get_or_create();
		if (new_encap_vrf != old_encap_vrf && vrf_incref(new_encap_vrf) < 0)
			return -errno;
	}

	if (set_attrs & GR_SR6_SET_FLAGS) {
		if (next->flags & ~GR_SR6_F_VALID) {
			if (new_encap_vrf != old_encap_vrf)
				vrf_decref(new_encap_vrf);
			return errno_set(EINVAL);
		}
	}

	if (set_attrs & GR_SR6_SET_MAC) {
		if (iface_set_eth_addr(iface, &next->mac) < 0) {
			if (new_encap_vrf != old_encap_vrf)
				vrf_decref(new_encap_vrf);
			return -errno;
		}
	}

	// Everything validated: apply.
	if (new_encap_vrf != old_encap_vrf) {
		cur->encap_vrf_id = new_encap_vrf;
		vrf_decref(old_encap_vrf);
	}
	if (set_attrs & GR_SR6_SET_FLAGS)
		cur->flags = next->flags;
	if (set_attrs & GR_SR6_SET_VLAN)
		cur->vlan_id = next->vlan_id;
	if (set_attrs & GR_SR6_SET_SID)
		cur->remote_sid = next->remote_sid;
	if (set_attrs & GR_SR6_SET_ENCAP)
		cur->encap = next->encap;

	return 0;
}

static int iface_sr6_init(struct iface *iface, const void *api_info) {
	struct gr_iface conf;
	int ret;

	iface->speed = RTE_ETH_SPEED_NUM_10G;
	if (iface->mtu == 0)
		iface->mtu = 1500;

	conf.base = iface->base;

	ret = iface_sr6_reconfig(iface, IFACE_SET_ALL, &conf, api_info);
	if (ret < 0) {
		errno = -ret;
		return ret;
	}

	return 0;
}

static int iface_sr6_fini(struct iface *iface) {
	struct iface_info_sr6 *sr6 = iface_info_sr6(iface);

	if (sr6->encap_vrf_id != GR_VRF_ID_UNDEF)
		vrf_decref(sr6->encap_vrf_id);

	return 0;
}

static int iface_sr6_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	*mac = iface_info_sr6(iface)->mac;

	return 0;
}

static int iface_sr6_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_sr6 *sr6 = iface_info_sr6(iface);

	if (rte_is_zero_ether_addr(mac))
		rte_eth_random_addr(sr6->mac.addr_bytes);
	else
		sr6->mac = *mac;

	return 0;
}

static void sr6_to_api(void *info, const struct iface *iface) {
	const struct iface_info_sr6 *sr6 = iface_info_sr6(iface);
	struct gr_iface_info_sr6 *api = info;

	*api = sr6->base;
}

static const struct iface_type iface_type_sr6 = {
	.id = GR_IFACE_TYPE_SR6,
	.pub_size = sizeof(struct gr_iface_info_sr6),
	.priv_size = sizeof(struct iface_info_sr6),
	.init = iface_sr6_init,
	.reconfig = iface_sr6_reconfig,
	.fini = iface_sr6_fini,
	.get_eth_addr = iface_sr6_get_eth_addr,
	.set_eth_addr = iface_sr6_set_eth_addr,
	.to_api = sr6_to_api,
};

RTE_INIT(sr6_iface_constructor) {
	iface_type_register(&iface_type_sr6);
}
