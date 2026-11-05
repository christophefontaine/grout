// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine, Red Hat

#include "acl.h"
#include "ip4_datapath.h"
#include "ip6_datapath.h"
#include "log.h"

#include <rte_byteorder.h>
#include <rte_ip6.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <string.h>

LOG_TYPE("acl");

// Fill the layer 4 fields of the key (ports and, for TCP, the flags).
// The field offsets depend on the address family (see the key layouts in
// acl.h). When the layer 4 header cannot be parsed (truncated packet),
// the zeroed bytes may wrongly match rules constraining a zero port or
// ICMP type/code: fail closed.
static void acl_key_fill_l4(
	uint8_t *key,
	const struct rte_mbuf *m,
	const uint8_t *l4,
	uint32_t off_sport,
	uint32_t off_dport,
	uint32_t off_flags
) {
	const struct rte_tcp_hdr *tcp;
	const struct rte_udp_hdr *udp;
	size_t l4_off = l4 - rte_pktmbuf_mtod(m, const uint8_t *);

	if (rte_pktmbuf_data_len(m) < l4_off + 4)
		return;

	// The proto byte is at offset 0 in both key layouts. sport and dport
	// are at the same offsets in the TCP and UDP headers; for ICMP, the
	// same bytes carry the type and code.
	switch (key[0]) {
	case IPPROTO_TCP:
		tcp = (const struct rte_tcp_hdr *)l4;
		*(rte_be16_t *)(key + off_sport) = tcp->src_port;
		*(rte_be16_t *)(key + off_dport) = tcp->dst_port;
		if (rte_pktmbuf_data_len(m) >= l4_off + sizeof(*tcp))
			key[off_flags] = tcp->tcp_flags;
		break;
	case IPPROTO_UDP:
		udp = (const struct rte_udp_hdr *)l4;
		*(rte_be16_t *)(key + off_sport) = udp->src_port;
		*(rte_be16_t *)(key + off_dport) = udp->dst_port;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		*(rte_be16_t *)(key + off_sport) = *(const rte_be16_t *)l4;
		break;
	}
}

static bool acl_classify(const struct acl_class *acl, const uint8_t *key) {
	uint32_t result = 0; // 0 is reserved: no rule matched
	int ret;

	ret = rte_acl_classify(acl->acl, &key, &result, 1, 1);
	if (ret != 0 || result == 0)
		return false;

	atomic_fetch_add_explicit(&acl->results[result].stats->pkts, 1, memory_order_relaxed);
	// Only the drop action is implemented: filters with the mark action
	// are rejected by the control plane.
	return true;
}

bool gr_acl_input_drop4(
	const struct acl_class *acl,
	const struct rte_mbuf *m,
	const struct rte_ipv4_hdr *ip
) {
	uint16_t frag_off = rte_be_to_cpu_16(ip->fragment_offset);
	uint8_t key[32] = {0}; // padded: the trie may read past the last field
	size_t l3_len = rte_ipv4_hdr_len(ip);

	key[ACL4_OFF_PROTO] = ip->next_proto_id;
	key[ACL4_OFF_DSCP] = ip->type_of_service >> 2;
	if (frag_off & 0x4000)
		key[ACL4_OFF_FRAG_FLAGS] |= ACL_FRAG_DONT;
	if (frag_off & 0x2000)
		key[ACL4_OFF_FRAG_FLAGS] |= ACL_FRAG_MORE;
	*(uint16_t *)(key + ACL4_OFF_FRAG_OFFSET) =
		rte_cpu_to_be_16(frag_off & RTE_IPV4_HDR_OFFSET_MASK);
	*(rte_be32_t *)(key + ACL4_OFF_SRC) = ip->src_addr;
	*(rte_be32_t *)(key + ACL4_OFF_DST) = ip->dst_addr;
	*(rte_be16_t *)(key + ACL4_OFF_PKT_LEN) = ip->total_length;

	// A fragment with a non zero offset does not carry the transport
	// header: leave the layer 4 key bytes zeroed instead of parsing
	// payload bytes as ports (fail closed).
	if (acl->l4 && l3_len >= sizeof(*ip) && (frag_off & RTE_IPV4_HDR_OFFSET_MASK) == 0)
		acl_key_fill_l4(
			key, m, (const uint8_t *)ip + l3_len, ACL4_OFF_SPORT, ACL4_OFF_DPORT,
			ACL4_OFF_TCP_FLAGS
		);

	return acl_classify(acl, key);
}

// Walk the IPv6 extension headers to find the transport protocol and the
// start of the layer 4 header. Returns a pointer to the transport header
// or NULL when it cannot be located (non-first fragment, malformed
// chain, too many headers). The transport protocol is stored back into
// *proto.
static const uint8_t *acl_ip6_find_l4(
	const struct rte_mbuf *m, const struct rte_ipv6_hdr *ip, uint8_t *proto
) {
	const uint8_t *l4 = (const uint8_t *)ip + sizeof(*ip);
	size_t data_len = rte_pktmbuf_data_len(m);

	// Walk the extension header chain. The common case (no extension
	// headers) is a single switch fallthrough.
	for (int i = 0; i < 8; i++) {
		size_t ext_len;

		if (*proto != IPPROTO_HOPOPTS && *proto != IPPROTO_ROUTING
		    && *proto != IPPROTO_DSTOPTS && *proto != IPPROTO_FRAGMENT
		    && *proto != IPPROTO_AH) {
			// transport protocol reached
			return l4;
		}

		// Extension headers are at least 8 bytes long: make sure the
		// whole header is within the packet before reading it.
		if ((size_t)(l4 - (const uint8_t *)ip) + 8 > data_len)
			return NULL; // truncated packet

		if (*proto == IPPROTO_FRAGMENT) {
			// Only the first fragment (offset == 0) carries the
			// transport header. Non-first fragments have their
			// L4 bytes in other packets.
			const struct rte_ipv6_fragment_ext *frag =
				(const struct rte_ipv6_fragment_ext *)l4;
			if ((rte_be_to_cpu_16(frag->frag_data) & 0xfff8) != 0)
				return NULL; // non-first fragment
		}

		int next = rte_ipv6_get_next_ext(l4, *proto, &ext_len);
		if (next < 0)
			return NULL; // malformed extension header

		*proto = (uint8_t)next;
		l4 += ext_len;
	}

	return NULL; // too many extension headers
}

bool gr_acl_input_drop6(
	const struct acl_class *acl,
	const struct rte_mbuf *m,
	const struct rte_ipv6_hdr *ip
) {
	uint32_t vtc_flow = rte_be_to_cpu_32(ip->vtc_flow);
	uint8_t key[56] = {0}; // padded: the trie may read past the last field
	uint8_t proto = ip->proto;
	const uint8_t *l4;

	key[ACL6_OFF_PROTO] = proto;
	key[ACL6_OFF_DSCP] = (vtc_flow >> 22) & 0x3f;
	*(rte_be16_t *)(key + ACL6_OFF_PKT_LEN) = rte_cpu_to_be_16(
		rte_be_to_cpu_16(ip->payload_len) + sizeof(*ip)
	);
	*(rte_be32_t *)(key + ACL6_OFF_FLOW_LABEL) = rte_cpu_to_be_32(vtc_flow & 0xfffff);
	memcpy(key + ACL6_OFF_SRC, &ip->src_addr, sizeof(ip->src_addr));
	memcpy(key + ACL6_OFF_DST, &ip->dst_addr, sizeof(ip->dst_addr));

	if (acl->l4) {
		l4 = acl_ip6_find_l4(m, ip, &proto);
		if (l4 != NULL) {
			// Use the actual transport protocol, not the first
			// extension header type.
			key[ACL6_OFF_PROTO] = proto;
			acl_key_fill_l4(
				key, m, l4, ACL6_OFF_SPORT, ACL6_OFF_DPORT, ACL6_OFF_TCP_FLAGS
			);
		}
	}

	return acl_classify(acl, key);
}
