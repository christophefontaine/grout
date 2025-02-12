// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#ifndef _GR_L2
#define _GR_L2

#include <gr_api.h>
#include <gr_infra.h>

#define GR_L2_MODULE 0x1212
#define GR_L2_MODE_SET REQUEST_TYPE(GR_L2_MODULE, 0x0001)

struct gr_l2_iface_mode_req {
	enum gr_iface_mode mode;
	uint16_t iface_id;
	uint16_t domain_id;
};
// struct gr_l2_iface_mode_resp { };

#endif
