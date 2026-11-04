// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#include "module.h"

#include <gr_acl.h>

#include <errno.h>

// The ACL control plane is not implemented yet: handlers only validate
// requests and return ENOSYS. Storage, datapath programming and events will
// be added in a later change.

static struct api_out acl_set_add(const void *request, struct api_ctx *) {
	const struct gr_acl_set_add_req *req = request;

	if (req->set.af != GR_AF_IP4 && req->set.af != GR_AF_IP6)
		return api_out(EINVAL, 0, NULL);
	if (req->set.type < GR_ACL_SET_NET_NET || req->set.type > GR_ACL_SET_NET)
		return api_out(EINVAL, 0, NULL);

	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_set_del(const void *request, struct api_ctx *) {
	const struct gr_acl_set_del_req *req = request;

	if (req->set_id == 0)
		return api_out(EINVAL, 0, NULL);

	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_set_list(const void *, struct api_ctx *) {
	return api_out(ENOSYS, 0, NULL);
}

static bool acl_net_valid(const struct gr_acl_net *net, addr_family_t af) {
	if (net->af == GR_AF_UNSPEC)
		return true;
	if (net->af != af)
		return false;
	if (af == GR_AF_IP4)
		return net->prefixlen <= 32;
	if (af == GR_AF_IP6)
		return net->prefixlen <= 128;
	return false;
}

static struct api_out acl_entry_add(const void *request, struct api_ctx *) {
	const struct gr_acl_entry_add_req *req = request;
	addr_family_t af = req->entry.src.af;

	if (af == GR_AF_UNSPEC)
		af = req->entry.dst.af;
	if (af != GR_AF_IP4 && af != GR_AF_IP6)
		return api_out(EINVAL, 0, NULL);
	if (!acl_net_valid(&req->entry.src, af) || !acl_net_valid(&req->entry.dst, af))
		return api_out(EINVAL, 0, NULL);

	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_entry_del(const void *request, struct api_ctx *) {
	const struct gr_acl_entry_del_req *req = request;

	if (req->set_id == 0 || req->entry_id == 0)
		return api_out(EINVAL, 0, NULL);

	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_entry_list(const void *, struct api_ctx *) {
	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_filter_add(const void *request, struct api_ctx *) {
	const struct gr_acl_filter_add_req *req = request;

	if (req->filter.af != GR_AF_IP4 && req->filter.af != GR_AF_IP6)
		return api_out(EINVAL, 0, NULL);
	if (req->filter.action != GR_ACL_ACTION_DROP && req->filter.action != GR_ACL_ACTION_MARK)
		return api_out(EINVAL, 0, NULL);
	if (req->filter.match_bm & ~GR_ACL_MATCH_VALID)
		return api_out(EINVAL, 0, NULL);

	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_filter_del(const void *request, struct api_ctx *) {
	const struct gr_acl_filter_del_req *req = request;

	if (req->filter_id == 0)
		return api_out(EINVAL, 0, NULL);

	return api_out(ENOSYS, 0, NULL);
}

static struct api_out acl_filter_list(const void *, struct api_ctx *) {
	return api_out(ENOSYS, 0, NULL);
}

RTE_INIT(acl_init) {
	api_handler(GR_ACL_SET_ADD, acl_set_add);
	api_handler(GR_ACL_SET_DEL, acl_set_del);
	api_handler(GR_ACL_SET_LIST, acl_set_list);
	api_handler(GR_ACL_ENTRY_ADD, acl_entry_add);
	api_handler(GR_ACL_ENTRY_DEL, acl_entry_del);
	api_handler(GR_ACL_ENTRY_LIST, acl_entry_list);
	api_handler(GR_ACL_FILTER_ADD, acl_filter_add);
	api_handler(GR_ACL_FILTER_DEL, acl_filter_del);
	api_handler(GR_ACL_FILTER_LIST, acl_filter_list);
}
