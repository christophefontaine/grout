// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_log.h>
#include <br_worker.h>

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#include <stdatomic.h>

enum tx_next_nodes {
	TX_NEXT_DROP,
	TX_NEXT_MAX,
};

struct tx_node_ctx {
	uint16_t port_id;
	uint16_t txq_id;
};

static uint16_t
tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint16_t count;

#if 0
	for (uint16_t c = 0; c < nb_objs; c++) {
		struct rte_mbuf *mbuf = objs[c];
		const struct rte_ether_hdr *eth_hdr;
		struct rte_ether_hdr eth_hdr_;

		eth_hdr = rte_pktmbuf_read(mbuf, 0, sizeof(eth_hdr_), &eth_hdr_);
		uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

		LOG(INFO,
		    "TX port %u queue %u: %02x:%02x:%02x:%02x:%02x:%02x > "
		    "%02x:%02x:%02x:%02x:%02x:%02x (0x%04x) len=%u",
		    ctx->port_id,
		    ctx->txq_id,
		    eth_hdr->src_addr.addr_bytes[0],
		    eth_hdr->src_addr.addr_bytes[1],
		    eth_hdr->src_addr.addr_bytes[2],
		    eth_hdr->src_addr.addr_bytes[3],
		    eth_hdr->src_addr.addr_bytes[4],
		    eth_hdr->src_addr.addr_bytes[5],
		    eth_hdr->dst_addr.addr_bytes[0],
		    eth_hdr->dst_addr.addr_bytes[1],
		    eth_hdr->dst_addr.addr_bytes[2],
		    eth_hdr->dst_addr.addr_bytes[3],
		    eth_hdr->dst_addr.addr_bytes[4],
		    eth_hdr->dst_addr.addr_bytes[5],
		    eth_type,
		    mbuf->pkt_len);
	}
#endif

	count = rte_eth_tx_burst(ctx->port_id, ctx->txq_id, (struct rte_mbuf **)objs, nb_objs);
	if (count != nb_objs)
		rte_node_enqueue(graph, node, TX_NEXT_DROP, &objs[count], nb_objs - count);

	return count;
}

static int tx_init(const struct rte_graph *graph, struct rte_node *node) {
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	struct queue_map *qmap;
	struct worker *worker;
	char name[BUFSIZ];
	uint8_t index;

	LIST_FOREACH (worker, &workers, next) {
		index = !atomic_load(&worker->cur_config);
		snprintf(name, sizeof(name), "br-%u-%u", index, worker->lcore_id);
		if (strcmp(name, graph->name) != 0)
			continue;

		LIST_FOREACH (qmap, &worker->rxqs, next) {
			snprintf(
				name,
				sizeof(name),
				"%s-%u-%u",
				node->parent,
				qmap->port_id,
				qmap->queue_id
			);
			if (strcmp(name, node->name) == 0) {
				ctx->port_id = qmap->port_id;
				ctx->txq_id = qmap->queue_id;
				return 0;
			}
		}
	}

	LOG(ERR, "no tx queue map found for node %s", node->name);
	return -ENOENT;
}

static struct rte_node_register tx_node_base = {
	.process = tx_process,
	.name = "br_tx",

	.init = tx_init,

	.nb_edges = TX_NEXT_MAX,
	.next_nodes = {
		[TX_NEXT_DROP] = "br_drop",
	},
};

RTE_NODE_REGISTER(tx_node_base);
