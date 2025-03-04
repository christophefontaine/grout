// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "module.h"

#include <gr_api.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vec.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

static STAILQ_HEAD(, gr_api_handler) handlers = STAILQ_HEAD_INITIALIZER(handlers);

void gr_register_api_handler(struct gr_api_handler *handler) {
	const struct gr_api_handler *h;

	assert(handler != NULL);
	assert(handler->callback != NULL);
	assert(handler->name != NULL);
	switch (handler->request_type) {
	case GR_MAIN_HELLO:
	case GR_MAIN_EVENT_SUBSCRIBE:
	case GR_MAIN_EVENT_UNSUBSCRIBE:
		goto duplicate;
	}

	STAILQ_FOREACH (h, &handlers, entries) {
		if (h->request_type == handler->request_type)
duplicate:
			ABORT("duplicate api handler type=0x%08x '%s'",
			      handler->request_type,
			      handler->name);
	}
	STAILQ_INSERT_TAIL(&handlers, handler, entries);
}

const struct gr_api_handler *lookup_api_handler(const struct gr_api_request *req) {
	const struct gr_api_handler *handler;

	STAILQ_FOREACH (handler, &handlers, entries) {
		if (handler->request_type == req->type)
			return handler;
	}

	return NULL;
}

static STAILQ_HEAD(, gr_module) modules = STAILQ_HEAD_INITIALIZER(modules);

void gr_register_module(struct gr_module *mod) {
	if (mod->name == NULL)
		ABORT("module with no name: %p", mod);
	STAILQ_INSERT_TAIL(&modules, mod, entries);
}

static int module_init_prio_order(const void *a, const void *b) {
	const struct gr_module *const *mod_a = a;
	const struct gr_module *const *mod_b = b;
	return (*mod_a)->init_prio - (*mod_b)->init_prio;
}

void modules_init(struct event_base *ev_base) {
	struct gr_module *mod, **mods = NULL;

	STAILQ_FOREACH (mod, &modules, entries)
		gr_vec_add(mods, mod);

	if (mods == NULL)
		ABORT("failed to alloc module array");

	qsort(mods, gr_vec_len(mods), sizeof(struct gr_module *), module_init_prio_order);

	gr_vec_foreach (mod, mods) {
		if (mod->init != NULL) {
			LOG(DEBUG, "%s prio %i", mod->name, mod->init_prio);
			mod->init(ev_base);
		}
	}

	gr_vec_free(mods);
}

static int module_fini_prio_order(const void *a, const void *b) {
	const struct gr_module *const *mod_a = a;
	const struct gr_module *const *mod_b = b;
	return (*mod_a)->fini_prio - (*mod_b)->fini_prio;
}

void modules_fini(struct event_base *ev_base) {
	struct gr_module *mod, **mods = NULL;

	STAILQ_FOREACH (mod, &modules, entries)
		gr_vec_add(mods, mod);

	if (mods == NULL)
		ABORT("failed to alloc module array");

	qsort(mods, gr_vec_len(mods), sizeof(struct gr_module *), module_fini_prio_order);

	gr_vec_foreach (mod, mods) {
		if (mod->fini != NULL) {
			LOG(DEBUG, "%s prio %i", mod->name, mod->fini_prio);
			mod->fini(ev_base);
		}
	}

	gr_vec_free(mods);
}

void gr_modules_dp_init(void) {
	struct gr_module *mod;

	STAILQ_FOREACH (mod, &modules, entries) {
		if (mod->init_dp != NULL) {
			LOG(DEBUG, "%s", mod->name);
			mod->init_dp();
		}
	}
}

void gr_modules_dp_fini(void) {
	struct gr_module *mod;

	STAILQ_FOREACH (mod, &modules, entries) {
		if (mod->fini_dp != NULL) {
			LOG(DEBUG, "%s", mod->name);
			mod->fini_dp();
		}
	}
}
