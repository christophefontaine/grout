// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "api.h"

#include <gr_api.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_queue.h>
#include <gr_vec.h>

#include <event2/event.h>

#include <stdatomic.h>
#include <string.h>

STAILQ_HEAD(subscribers, gr_event_subscription);
static struct subscribers subscribers = STAILQ_HEAD_INITIALIZER(subscribers);

void gr_event_subscribe(struct gr_event_subscription *sub) {
	STAILQ_INSERT_TAIL(&subscribers, sub, next);
}

struct event_obj {
	uint32_t type;
	size_t obj_sz;
	uint8_t obj[];
};
static gr_vec struct event_obj **evt_queue = NULL;
static struct event *push_ev;

void gr_event_enqueue(uint32_t ev_type, const void *obj, const size_t obj_sz) {
	struct event_obj *evt = malloc(sizeof(*evt) + obj_sz);
	evt->type = ev_type;
	evt->obj_sz = obj_sz;
	memcpy(evt->obj, obj, obj_sz);
	gr_vec_insert(evt_queue, 0, evt);
	evuser_trigger(push_ev);
}

static void push_evt_cb(evutil_socket_t, short, void *) {
	const struct gr_event_subscription *sub;
	struct event_obj *evt;

	if (gr_vec_len(evt_queue) == 0)
		return;

	evt = gr_vec_pop(evt_queue);
	STAILQ_FOREACH (sub, &subscribers, next) {
		for (unsigned i = 0; i < sub->ev_count; i++) {
			if (sub->ev_types[i] == evt->type || sub->ev_types[i] == EVENT_TYPE_ALL) {
				if (evt->obj_sz == sizeof(uintptr_t))
					sub->callback(evt->type, *(void **)evt->obj);
				else
					sub->callback(evt->type, evt->obj);
				break;
			}
		}
	}
	api_send_notifications(evt->type, evt->obj);

	free(evt);
	if (gr_vec_len(evt_queue) > 0)
		evuser_trigger(push_ev);
}

STAILQ_HEAD(serializers, gr_event_serializer);
static struct serializers serializers = STAILQ_HEAD_INITIALIZER(serializers);

void gr_event_register_serializer(struct gr_event_serializer *serializer) {
	struct gr_event_serializer *s;

	if (serializer == NULL)
		ABORT("NULL serializer");
	if (serializer->callback == NULL && serializer->size == 0)
		ABORT("one of callback or size are required");
	if (serializer->callback != NULL && serializer->size != 0)
		ABORT("callback and size are mutually exclusive");

	STAILQ_FOREACH (s, &serializers, next) {
		for (unsigned i = 0; i < s->ev_count; i++) {
			for (unsigned j = 0; j < serializer->ev_count; j++) {
				if (s->ev_types[i] == serializer->ev_types[j])
					ABORT("duplicate serializer for event 0x%08x",
					      serializer->ev_types[j]);
			}
		}
	}
	STAILQ_INSERT_TAIL(&serializers, serializer, next);
}

int gr_event_serialize(uint32_t ev_type, const void *obj, void **buf) {
	struct gr_event_serializer *s;

	STAILQ_FOREACH (s, &serializers, next) {
		for (unsigned i = 0; i < s->ev_count; i++) {
			if (s->ev_types[i] == ev_type) {
				if (s->callback != NULL)
					return s->callback(obj, buf);

				void *data = malloc(s->size);
				if (data == NULL)
					return errno_set(ENOMEM);

				memcpy(data, obj, s->size);
				*buf = data;

				return s->size;
			}
		}
	}
	ABORT("no registered serializer for event 0x%08x", ev_type);
}

static void event_init(struct event_base *ev_base) {
	push_ev = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, push_evt_cb, NULL);
	if (push_ev == NULL)
		ABORT("event_new() failed");
}

static void event_fini(struct event_base *) {
	event_free(push_ev);
}

static struct gr_module event_module = {
	.name = "event",
	.depends_on = "graph",
	.init = event_init,
	.fini = event_fini,
};

RTE_INIT(event_module_init) {
	gr_register_module(&event_module);
}
