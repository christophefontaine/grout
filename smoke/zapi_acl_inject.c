// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

// Raw ZAPI client used by smoke/acl_frr_test.sh to validate the ACL
// pipeline between zebra and the grout dataplane plugin. It programs the
// PBR netfilter objects (ipset, ipset entry, iptable) that BGP flowspec
// uses for ACLs directly through the zserv socket, without needing bgpd,
// and checks the notifications sent back by zebra.
//
// The programmed objects drop all traffic with a source address of
// 172.16.0.2 (the smoke test netns peer) arriving on the interface
// passed with -i.

#include <gr_clock.h>

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define ZEBRA_HEADER_MARKER 254
#define ZSERV_VERSION 6
#define ZEBRA_HEADER_SIZE 10
#define ZEBRA_IPSET_NAME_SIZE 32

// Values of enum zebra_message (lib/zclient.h).
enum {
	ZEBRA_IPSET_CREATE = 90,
	ZEBRA_IPSET_DESTROY = 91,
	ZEBRA_IPSET_ENTRY_ADD = 92,
	ZEBRA_IPSET_ENTRY_DELETE = 93,
	ZEBRA_IPSET_NOTIFY_OWNER = 94,
	ZEBRA_IPSET_ENTRY_NOTIFY_OWNER = 95,
	ZEBRA_IPTABLE_ADD = 96,
	ZEBRA_IPTABLE_DELETE = 97,
	ZEBRA_IPTABLE_NOTIFY_OWNER = 98,
};

// Values of enum zapi_ipset_notify_owner & friends (lib/zclient.h).
enum {
	ZAPI_FAIL_INSTALL = 0,
	ZAPI_INSTALLED = 1,
	ZAPI_REMOVED = 2,
	ZAPI_FAIL_REMOVE = 3,
};

// The grout ACL API is implemented: the operations must succeed.
#define EXPECT_INSTALL ZAPI_INSTALLED
#define EXPECT_REMOVE ZAPI_REMOVED

// Object identifiers, also used as zapi notification cookies.
#define IPSET_UNIQUE 100
#define ENTRY_UNIQUE 101
#define IPTABLE_UNIQUE 102
#define IPSET_NAME "TESTSET"

#define NOTIF_TIMEOUT_MS 3000

static int sock;
static int failures;

static const char *cmd_name(uint16_t cmd) {
	switch (cmd) {
	case ZEBRA_IPSET_CREATE:
		return "IPSET_CREATE";
	case ZEBRA_IPSET_DESTROY:
		return "IPSET_DESTROY";
	case ZEBRA_IPSET_ENTRY_ADD:
		return "IPSET_ENTRY_ADD";
	case ZEBRA_IPSET_ENTRY_DELETE:
		return "IPSET_ENTRY_DELETE";
	case ZEBRA_IPSET_NOTIFY_OWNER:
		return "IPSET_NOTIFY_OWNER";
	case ZEBRA_IPSET_ENTRY_NOTIFY_OWNER:
		return "IPSET_ENTRY_NOTIFY_OWNER";
	case ZEBRA_IPTABLE_ADD:
		return "IPTABLE_ADD";
	case ZEBRA_IPTABLE_DELETE:
		return "IPTABLE_DELETE";
	case ZEBRA_IPTABLE_NOTIFY_OWNER:
		return "IPTABLE_NOTIFY_OWNER";
	}
	return "?";
}

static const char *note_name(uint16_t note) {
	switch (note) {
	case ZAPI_FAIL_INSTALL:
		return "FAIL_INSTALL";
	case ZAPI_INSTALLED:
		return "INSTALLED";
	case ZAPI_REMOVED:
		return "REMOVED";
	case ZAPI_FAIL_REMOVE:
		return "FAIL_REMOVE";
	}
	return "?";
}

static void put16(uint8_t *b, size_t *n, uint16_t v) {
	b[(*n)++] = v >> 8;
	b[(*n)++] = v;
}

static void put32(uint8_t *b, size_t *n, uint32_t v) {
	b[(*n)++] = v >> 24;
	b[(*n)++] = v >> 16;
	b[(*n)++] = v >> 8;
	b[(*n)++] = v;
}

static void put_name(uint8_t *b, size_t *n) {
	memset(b + *n, 0, ZEBRA_IPSET_NAME_SIZE);
	memcpy(b + *n, IPSET_NAME, sizeof(IPSET_NAME) - 1);
	*n += ZEBRA_IPSET_NAME_SIZE;
}

static void send_msg(uint16_t cmd, const uint8_t *body, size_t body_len) {
	uint8_t pkt[512];
	size_t n = 0;

	put16(pkt, &n, ZEBRA_HEADER_SIZE + body_len);
	pkt[n++] = ZEBRA_HEADER_MARKER;
	pkt[n++] = ZSERV_VERSION;
	put32(pkt, &n, 0); // vrf_id
	put16(pkt, &n, cmd);
	memcpy(pkt + n, body, body_len);
	n += body_len;

	if (write(sock, pkt, n) < 0) {
		perror("write");
		exit(1);
	}
	printf(">>> %s\n", cmd_name(cmd));
}

static ssize_t read_fully(uint8_t *buf, size_t len) {
	size_t got = 0;

	while (got < len) {
		ssize_t r = read(sock, buf + got, len - got);

		if (r < 0)
			return -1;
		if (r == 0)
			return 0;
		got += r;
	}
	return got;
}

static uint64_t now_ms(void) {
	return gr_clock_ns() / GR_NS_PER_MS;
}

struct notification {
	uint16_t cmd;
	uint16_t note;
	uint32_t unique;
	char name[ZEBRA_IPSET_NAME_SIZE + 1];
};

// Read the next PBR netfilter notification, skipping the other messages
// zebra broadcasts to its clients (interface, VRF updates...).
static int read_notification(struct notification *notif, int timeout_ms) {
	uint8_t hdr[ZEBRA_HEADER_SIZE], body[128];
	uint64_t deadline = now_ms() + timeout_ms;
	uint16_t len, cmd;

	for (;;) {
		struct pollfd pfd = {.fd = sock, .events = POLLIN};
		int64_t remaining = deadline - now_ms();
		uint32_t unique;
		uint16_t note;
		size_t body_len;

		if (remaining <= 0 || poll(&pfd, 1, remaining) <= 0) {
			fprintf(stderr, "timeout waiting for a notification\n");
			return -1;
		}
		if (read_fully(hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
			return -1;

		len = hdr[0] << 8 | hdr[1];
		cmd = hdr[8] << 8 | hdr[9];
		body_len = len - sizeof(hdr);

		if (body_len >= sizeof(body)) {
			// oversized message: discard it chunk by chunk
			while (body_len > 0) {
				size_t chunk = body_len < sizeof(body) ? body_len : sizeof(body);

				if (read_fully(body, chunk) != (ssize_t)chunk)
					return -1;
				body_len -= chunk;
			}
			continue;
		}
		if (read_fully(body, body_len) != (ssize_t)body_len)
			return -1;

		if (cmd != ZEBRA_IPSET_NOTIFY_OWNER && cmd != ZEBRA_IPSET_ENTRY_NOTIFY_OWNER
		    && cmd != ZEBRA_IPTABLE_NOTIFY_OWNER)
			continue; // unrelated broadcast, skip it

		if (body_len < 6) {
			fprintf(stderr, "invalid notification length %u\n", len);
			return -1;
		}

		note = body[0] << 8 | body[1];
		unique = (uint32_t)body[2] << 24 | (uint32_t)body[3] << 16
			 | (uint32_t)body[4] << 8 | body[5];
		memcpy(notif->name, body + 6, body_len - 6);
		notif->name[body_len - 6] = '\0';

		notif->cmd = cmd;
		notif->note = note;
		notif->unique = unique;
		return 0;
	}
}

static void expect_notification_ms(
	uint16_t cmd,
	uint32_t unique,
	uint16_t expected_note,
	int timeout_ms
) {
	struct notification notif;

	if (read_notification(&notif, timeout_ms) < 0) {
		failures++;
		return;
	}
	printf("<<< %s note=%s unique=%u name=%s\n",
	       cmd_name(notif.cmd),
	       note_name(notif.note),
	       notif.unique,
	       notif.name);

	if (notif.cmd != cmd) {
		fprintf(stderr, "expected %s, got %s\n", cmd_name(cmd), cmd_name(notif.cmd));
		failures++;
	} else if (notif.unique != unique) {
		fprintf(stderr, "expected unique %u, got %u\n", unique, notif.unique);
		failures++;
	} else if (notif.note != expected_note) {
		fprintf(stderr,
			"expected note %s, got %s\n",
			note_name(expected_note),
			note_name(notif.note));
		failures++;
	}
}

static void expect_notification(uint16_t cmd, uint32_t unique, uint16_t expected_note) {
	expect_notification_ms(cmd, unique, expected_note, NOTIF_TIMEOUT_MS);
}

// IPSET_CREATE / IPSET_DESTROY: total, unique, type, family, name.
static void send_ipset(uint16_t cmd) {
	uint8_t body[64];
	size_t n = 0;

	put32(body, &n, 1); // total
	put32(body, &n, IPSET_UNIQUE);
	put32(body, &n, 1); // IPSET_NET
	body[n++] = AF_INET;
	put_name(body, &n);
	send_msg(cmd, body, n);
}

// IPSET_ENTRY_ADD / IPSET_ENTRY_DELETE: total, unique, name, src, dst,
// ports, protocol. All fields are wildcards except the source prefix
// (172.16.0.2/32): the filter drops all traffic from that address.
static void send_ipset_entry(uint16_t cmd) {
	uint32_t src = inet_addr("172.16.0.2");
	uint8_t body[128];
	size_t n = 0;

	put32(body, &n, 1); // total
	put32(body, &n, ENTRY_UNIQUE);
	put_name(body, &n);
	body[n++] = AF_INET;
	body[n++] = 32;
	memcpy(body + n, &src, 4);
	n += 4;
	body[n++] = AF_INET; // dst: wildcard
	body[n++] = 0;
	put32(body, &n, 0); // dst address (ignored for /0)
	put16(body, &n, 0); // src_port_min
	put16(body, &n, 0); // src_port_max
	put16(body, &n, 0); // dst_port_min
	put16(body, &n, 0); // dst_port_max
	body[n++] = 0; // proto wildcard
	send_msg(cmd, body, n);
}

// IPTABLE_ADD / IPTABLE_DELETE: unique, type, filter_bm, action, fwmark,
// name, family, packet length, TCP flags, dscp, fragment, protocol, flow
// label, interface list.
static void send_iptable(uint16_t cmd, uint32_t ifindex) {
	uint8_t body[128];
	size_t n = 0;

	put32(body, &n, IPTABLE_UNIQUE);
	put32(body, &n, 1); // IPSET_NET
	put32(body, &n, 1 << 0); // MATCH_IP_SRC_SET
	put32(body, &n, 1); // ZEBRA_IPTABLES_DROP
	put32(body, &n, 0); // fwmark
	put_name(body, &n);
	body[n++] = AF_INET;
	put16(body, &n, 0); // pkt_len_min
	put16(body, &n, 0); // pkt_len_max
	put16(body, &n, 0); // tcp_flags
	put16(body, &n, 0); // tcp_mask_flags
	body[n++] = 0; // dscp
	body[n++] = 0; // fragment
	body[n++] = 0; // protocol
	put16(body, &n, 0); // flow_label
	if (ifindex != 0) {
		put32(body, &n, 1); // nb_interface
		put32(body, &n, ifindex);
	} else {
		put32(body, &n, 0); // nb_interface
	}
	send_msg(cmd, body, n);
}

static void usage(const char *prog) {
	fprintf(stderr, "usage: %s [-a] [-d] [-i IFINDEX] [-s SECONDS] [-w SECONDS] ZSERV_SOCKET\n", prog);
}

int main(int argc, char **argv) {
	struct sockaddr_un sa = {.sun_family = AF_UNIX};
	unsigned int resync_wait = 0;
	unsigned int pause_sec = 0;
	bool add_only = false;
	bool del_only = false;
	uint32_t ifindex = 0;
	const char *path;
	int opt;

	while ((opt = getopt(argc, argv, "adi:s:w:")) != -1) {
		switch (opt) {
		case 'a':
			add_only = true;
			break;
		case 'd':
			del_only = true;
			break;
		case 'i':
			ifindex = strtoul(optarg, NULL, 0);
			break;
		case 's':
			pause_sec = strtoul(optarg, NULL, 0);
			break;
		case 'w':
			resync_wait = strtoul(optarg, NULL, 0);
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (optind >= argc || (add_only && del_only)) {
		usage(argv[0]);
		return 1;
	}
	path = argv[optind];

	strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0 || connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror(path);
		return 1;
	}
	printf("connected to %s\n", path);

	if (!del_only) {
		send_ipset(ZEBRA_IPSET_CREATE);
		expect_notification(ZEBRA_IPSET_NOTIFY_OWNER, IPSET_UNIQUE, EXPECT_INSTALL);

		send_ipset_entry(ZEBRA_IPSET_ENTRY_ADD);
		expect_notification(ZEBRA_IPSET_ENTRY_NOTIFY_OWNER, ENTRY_UNIQUE, EXPECT_INSTALL);

		send_iptable(ZEBRA_IPTABLE_ADD, ifindex);
		expect_notification(ZEBRA_IPTABLE_NOTIFY_OWNER, IPTABLE_UNIQUE, EXPECT_INSTALL);
	}

	// Pause between the install and uninstall phases so the caller can
	// check the datapath drop (used with the full cycle mode).
	if (pause_sec > 0) {
		printf("pausing %us before the delete sequence\n", pause_sec);
		sleep(pause_sec);
	}

	// The objects must stay installed for the resync round: -w implies
	// add only.
	if ((!add_only && resync_wait == 0) || del_only) {
		send_iptable(ZEBRA_IPTABLE_DELETE, ifindex);
		expect_notification(ZEBRA_IPTABLE_NOTIFY_OWNER, IPTABLE_UNIQUE, EXPECT_REMOVE);

		send_ipset_entry(ZEBRA_IPSET_ENTRY_DELETE);
		expect_notification(ZEBRA_IPSET_ENTRY_NOTIFY_OWNER, ENTRY_UNIQUE, EXPECT_REMOVE);

		send_ipset(ZEBRA_IPSET_DESTROY);
		expect_notification(ZEBRA_IPSET_NOTIFY_OWNER, IPSET_UNIQUE, EXPECT_REMOVE);
	}

	if (resync_wait > 0) {
		// Wait for the grout plugin to re-push the objects into a
		// restarted grout (ACL resync): the same three install
		// notifications are expected again, on this still connected
		// socket.
		printf("waiting up to %us for the ACL resync notifications\n", resync_wait);
		expect_notification_ms(
			ZEBRA_IPSET_NOTIFY_OWNER, IPSET_UNIQUE, EXPECT_INSTALL, resync_wait * 1000
		);
		expect_notification(ZEBRA_IPSET_ENTRY_NOTIFY_OWNER, ENTRY_UNIQUE, EXPECT_INSTALL);
		expect_notification(ZEBRA_IPTABLE_NOTIFY_OWNER, IPTABLE_UNIQUE, EXPECT_INSTALL);
	}

	close(sock);

	if (failures) {
		fprintf(stderr, "%d notification(s) mismatched\n", failures);
		return 1;
	}
	return 0;
}
