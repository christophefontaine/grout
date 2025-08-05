// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <stdint.h>

// TODO: make this configurable
#define IP4_MAX_ROUTES (1 << 16)

// Only for datapath use
const struct nexthop *fib4_lookup(uint16_t vrf_id, ip4_addr_t ip);
void fib4_lookup_x2(uint16_t vrf_id, ip4_addr_t ip[2], const struct nexthop *nh[2]);
void fib4_lookup_x4(
	uint16_t vrf_id,
	ip4_addr_t ip0,
	ip4_addr_t ip1,
	ip4_addr_t ip2,
	ip4_addr_t ip3,
	const struct nexthop *nhs[4]
);

// Only for control plane use to update the fib
int fib4_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, const struct nexthop *);
int fib4_remove(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
