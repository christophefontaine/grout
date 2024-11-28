// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_CLI_IP
#define _GR_CLI_IP

#include <gr_cli.h>

#define IP_ADD_CTX(root) CLI_CONTEXT(root, CTX_ADD, CTX_ARG("ip", "Create IPv4 stack elements."))
#define IP_DEL_CTX(root) CLI_CONTEXT(root, CTX_DEL, CTX_ARG("ip", "Delete IPv4 stack elements."))
#define IP_SET_CTX(root) CLI_CONTEXT(root, CTX_SET, CTX_ARG("ip", "Set IPv4 stack details."))
#define IP_SHOW_CTX(root) CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("ip", "Show IPv4 stack details."))

#endif
