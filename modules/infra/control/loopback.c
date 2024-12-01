// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_mempool.h>
#include <gr_module.h>

#include <event2/event.h>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TUN_TAP_DEV_PATH "/dev/net/tun"

static struct rte_mempool *loopback_pool;
static struct event_base *global_ev_base;

struct iface_info_loop {
	int fd;
	struct event *ev;
};

void loopback_tx(struct rte_mbuf *m) {
	struct mbuf_data *d = mbuf_data(m);
	struct iface_info_loop *loop;

	loop = (struct iface_info_loop *)d->iface->info;
	if (write(loop->fd, rte_pktmbuf_mtod(m, char *), m->data_len) < 0)
		LOG(ERR, "write to tun device %s failed %s", d->iface->name, strerror(errno));

	rte_pktmbuf_free(m);
}

static void iface_loopback_poll(evutil_socket_t, short, void *ev_iface) {
	struct eth_input_mbuf_data *e;
	struct iface_info_loop *loop;
	struct iface *iface = ev_iface;
	struct rte_mbuf *mbuf;
	size_t len;
	char *data;

	loop = (struct iface_info_loop *)iface->info;

	mbuf = rte_pktmbuf_alloc(loopback_pool);
	if (!mbuf)
		goto end;

	mbuf->data_off = 256;
	data = rte_pktmbuf_mtod(mbuf, char *);
	len = read(loop->fd, data, 1600);

	if (mbuf->buf_len <= 0) {
		rte_pktmbuf_free(mbuf);
		goto end;
	}
	mbuf->data_len = len;
	mbuf->pkt_len = mbuf->data_len;

	if ((*data & 0xf0) == 0x40) {
		mbuf->packet_type = RTE_PTYPE_L3_IPV4;
	} else if ((*data & 0xf0) == 0x60) {
		mbuf->packet_type = RTE_PTYPE_L3_IPV6;
		rte_pktmbuf_free(mbuf);
		goto end;
	} else {
		rte_pktmbuf_free(mbuf);
		goto end;
	}
	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
	// Emulate ethernet input, required by ip(6)_input
	e = eth_input_mbuf_data(mbuf);
	e->iface = iface;
	e->eth_dst = ETH_DST_LOCAL;

	post_to_stack(loopback_get_control_id(), mbuf);

end:
	event_add(loop->ev, NULL);
}

struct iface *iface_loopback_create(uint16_t vrf_id) {
	char ifname[64];
	snprintf(ifname, sizeof(ifname), "gr-loop%d", vrf_id);
	return iface_create(GR_IFACE_TYPE_LOOPBACK, 0, 0, vrf_id, ifname, NULL);
}

int iface_loopback_delete(uint16_t vrf_id) {
	const struct iface *i = NULL;
	while ((i = iface_next(GR_IFACE_TYPE_LOOPBACK, i)) != NULL)
		if (i->vrf_id == vrf_id)
			break;
	if (i == NULL)
		return -ENODEV;

	return iface_destroy(i->id);
}

static int iface_loop_init(struct iface *iface, const void * /* api_info */) {
	struct iface_info_loop *loop = (struct iface_info_loop *)iface->info;
	struct ifreq ifr;
	int ioctl_sock;
	int flags;

	memset(&ifr, 0, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, iface->name, IFNAMSIZ);
	ifr.ifr_flags = IFF_TUN | IFF_POINTOPOINT | IFF_NO_PI | IFF_ONE_QUEUE;

	loop->fd = open(TUN_TAP_DEV_PATH, O_RDWR);
	ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (ioctl(loop->fd, TUNSETIFF, &ifr) < 0)
		goto cleanup;

	flags = fcntl(loop->fd, F_GETFL);
	if (flags == -1)
		goto cleanup;

	flags |= O_NONBLOCK;
	if (fcntl(loop->fd, F_SETFL, flags) < 0)
		goto cleanup;

	if (ioctl(ioctl_sock, SIOCGIFFLAGS, &ifr) < 0)
		goto cleanup;

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(ioctl_sock, SIOCSIFFLAGS, &ifr) < 0)
		goto cleanup;

	iface->flags = GR_IFACE_F_UP;
	iface->state = GR_IFACE_S_RUNNING;
	loop->ev = event_new(global_ev_base, loop->fd, EV_READ, iface_loopback_poll, iface);
	event_add(loop->ev, NULL);
	close(ioctl_sock);
	return 0;

cleanup:
	printf("error: %s\n", strerror(errno));
	if (loop->fd > 0)
		close(loop->fd);
	if (ioctl_sock > 0)
		close(ioctl_sock);
	return -1;
}

static int iface_loop_fini(struct iface *iface) {
	struct iface_info_loop *loop = (struct iface_info_loop *)iface->info;
	event_del(loop->ev);
	event_free(loop->ev);
	close(loop->fd);
	return 0;
}

static void loop_init(struct event_base *ev_base) {
	loopback_pool = gr_pktmbuf_pool_get(SOCKET_ID_ANY, RTE_GRAPH_BURST_SIZE);
	global_ev_base = ev_base;
}

static void loop_fini(struct event_base *) {
	gr_pktmbuf_pool_release(loopback_pool, RTE_GRAPH_BURST_SIZE);
}

static void iface_loop_to_api(void * /* info */, const struct iface * /* iface */) { }

static struct iface_type iface_type_loopback = {
	.id = GR_IFACE_TYPE_LOOPBACK,
	.name = "loopback",
	.info_size = sizeof(struct iface_info_loop),
	.init = iface_loop_init,
	.fini = iface_loop_fini,
	.to_api = iface_loop_to_api,
};

static struct gr_module loopback_module = {
	.name = "iface loopback",
	.init = loop_init,
	.fini = loop_fini,
};

RTE_INIT(loopback_constructor) {
	iface_type_register(&iface_type_loopback);
	gr_register_module(&loopback_module);
}
