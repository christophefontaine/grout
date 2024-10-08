// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CORE_DPDK
#define _GR_CORE_DPDK

#include "gr.h"

int dpdk_log_init(const struct gr_args *);
int dpdk_init(const struct gr_args *);
void dpdk_fini(void);

#endif
