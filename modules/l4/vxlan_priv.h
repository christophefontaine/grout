// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#ifndef _VXLAN_PRIV_H
#define _VXLAN_PRIV_H

#include "gr_vxlan.h"

#include <gr_iface.h>
#include <gr_macro.h>
#include <gr_net_types.h>

struct __rte_aligned(alignof(void *)) iface_info_vxlan {
	BASE(gr_iface_info_vxlan);
};

struct iface *vxlan_get_iface(uint8_t family, const void* local, const void *remote, uint16_t vrf_id);

struct trace_vxlan_data {
	uint16_t iface_id;
	uint32_t vni;
};

int trace_vxlan_format(char *buf, size_t len, const void *data, size_t data_len);
#endif
