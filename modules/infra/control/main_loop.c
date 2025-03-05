// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr.h>
#include <gr_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_worker.h>

#include <rte_graph_worker.h>

static struct event *ctrlloop_ev;

static void control_loop(evutil_socket_t, short, void *) {
	struct worker *worker;

	STAILQ_FOREACH (worker, &workers, next) {
		if (worker->started && worker->ctl_graph)
			rte_graph_walk(worker->ctl_graph);
	}
}

static void control_loop_init(struct event_base *ev_base) {
	struct timeval time;
	time.tv_sec = 0;
	time.tv_usec = 100000;

	ctrlloop_ev = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, control_loop, NULL);
	evtimer_add(ctrlloop_ev, &time);
}

static void control_loop_fini(struct event_base *) {
	event_free(ctrlloop_ev);
}

static struct gr_module control_module = {
	.name = "control_loop",
	.init = control_loop_init,
	.fini = control_loop_fini,
};

RTE_INIT(control_module_init) {
	gr_register_module(&control_module);
}
