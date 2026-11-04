// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#pragma once

#include <zebra/zebra_dplane.h>

// DPLANE_OP_IPSET_ADD / DPLANE_OP_IPSET_DELETE
enum zebra_dplane_result grout_add_del_ipset(struct zebra_dplane_ctx *ctx);

// DPLANE_OP_IPSET_ENTRY_ADD / DPLANE_OP_IPSET_ENTRY_DELETE
enum zebra_dplane_result grout_add_del_ipset_entry(struct zebra_dplane_ctx *ctx);

// DPLANE_OP_IPTABLE_ADD / DPLANE_OP_IPTABLE_DELETE
enum zebra_dplane_result grout_add_del_iptable(struct zebra_dplane_ctx *ctx);

// Drop all ipset name -> grout set id mappings (called on grout reconnect).
void clear_acl_mappings(void);
