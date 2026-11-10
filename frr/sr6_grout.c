// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christophe Fontaine, Red Hat

// SRv6 L2 EVPN (RFC 9252) dataplane operations of the FRR fork carrying
// FRRouting PR #22570. The content of this file is only enabled when the
// plugin is built against that fork (meson frr_version 'srv6-l2evpn'
// defines HAVE_FRR_SRV6_L2EVPN): the operations do not exist in upstream
// FRR releases.
//
// Model mapping (kernel -> grout):
//
// The fork expects operator-created "sr6" tunnel netdevs ("sr6-<n>"
// unicast End.DT2U, "bum-sr6-<n>" BUM End.DT2M, "vpws-sr6-<name>"
// End.DX2) enslaved to an EVPN bridge. Zebra discovers them by name on
// the bridge and reprograms them in place through the new dataplane ops.
// With the grout plugin those interfaces are grout bridge members created
// by the operator (any member type, e.g. a vlan interface named "sr6-1");
// zebra discovers them the same way since the plugin reports grout
// interfaces with their names and bridge enslavement.
//
// - DPLANE_OP_SR6_UPDATE_SID sets the *encap* segment list of the tunnel
//   port (the remote PE SID; the all-zero SID resets the port). The
//   closest grout primitive is an SRv6 output nexthop (GR_NH_T_SR6_OUTPUT)
//   carrying the segment list, resolved by the underlay in the default
//   VRF. It is created with origin INTERNAL so that it does not echo back
//   into zebra. Since grout nexthops are keyed by (vrf, encap behavior,
//   segment list) and not by interface, the plugin keeps a per-port map
//   to release the previous nexthop when the segment changes. Once grout
//   grows the L2 SRv6 service datapath (End.DX2/DT2U/DT2M decap and L2
//   encap), the bridge ports can be bound to these nexthops.
//
// - DPLANE_OP_BRPORT_FLAGS pushes an EVPN bridge-port profile (learning
//   off, flooding per role, isolated) onto the tunnel port. grout bridges
//   have no per-port learning/flood/isolation knobs; the only expressible
//   part is per-interface FDB learning on VXLAN members, disabled when
//   the op targets a VXLAN interface (the traffic-less VNI anchor of the
//   fork's legacy model).
//
// - DPLANE_OP_BRIDGE_VLAN_ADD binds an EVI VLAN onto the tunnel port.
//   grout bridges are not VLAN-aware (no per-port VLAN filtering); the
//   EVI vlan is honored where it matters, in the FDB entries programmed
//   by the MAC install path with the same vlan id.

#ifdef HAVE_FRR_SRV6_L2EVPN

#include "if_map.h"
#include "log_grout.h"
#include "sr6_grout.h"
#include "zebra_dplane_grout.h"

#include <gr_infra.h>
#include <gr_l2.h>
#include <gr_srv6.h>

#include <lib/jhash.h>
#include <lib/typesafe.h>
#include <zebra/interface.h>

// Encap-mode values of the fork's enum zebra_sr6_encap_mode (zebra_sr6.h
// is not exported to plugins): FULL keeps the SRH on the wire, REDUCED is
// the single-SID H.Encaps.L2.Red flavor (SID in the IPv6 DA, no SRH).
#define SR6_ENCAP_MODE_FULL 0
#define SR6_ENCAP_MODE_REDUCED 1

// All functions in this file run exclusively on the dplane thread
// (zd_grout_process_update). No locking required.

// grout iface id -> current L2 encap segment //////////////////////////////////

PREDECL_HASH(sr6_port_hash);

struct sr6_port {
	struct sr6_port_hash_item item;
	struct in6_addr sid; // current encap segment, :: = none
	uint16_t iface_id;
	uint8_t mode; // SR6_ENCAP_MODE_*
};

static int sr6_port_cmp(const struct sr6_port *a, const struct sr6_port *b) {
	return numcmp(a->iface_id, b->iface_id);
}

static uint32_t sr6_port_hashfn(const struct sr6_port *e) {
	return e->iface_id;
}

DECLARE_HASH(sr6_port_hash, struct sr6_port, item, sr6_port_cmp, sr6_port_hashfn);
static struct sr6_port_hash_head sr6_ports = INIT_HASH(sr6_ports);

static struct sr6_port *sr6_port_lookup(uint16_t iface_id) {
	struct sr6_port key = {.iface_id = iface_id};

	return sr6_port_hash_find(&sr6_ports, &key);
}

// SRv6 L2 encap output nexthop ///////////////////////////////////////////////

// Fill the nexthop key of an L2 encap nexthop: one segment, encap behavior
// derived from the fork's encap mode, unspecified encap source so that
// grout uses the global SRv6 tunnel source (programmed through
// GR_SRV6_TUNSRC_SET by grout_set_sr_tunsrc()).
static void sr6_l2encap_nh_fill(struct gr_nexthop *nh, const struct in6_addr *sid, uint8_t mode) {
	struct gr_nexthop_info_srv6 *sr6 = (struct gr_nexthop_info_srv6 *)nh->info;

	memset(nh->info, 0, sizeof(*sr6) + sizeof(sr6->seglist[0]));

	nh->type = GR_NH_T_SR6_OUTPUT;
	// INTERNAL: no NEXTHOP_NEW/DELETE events back to zebra, no id
	// allocation, hidden from the default nexthop listings.
	nh->origin = GR_NH_ORIGIN_INTERNAL;
	// The underlay resolves the remote locator: encapsulated packets are
	// routed in the default VRF, like the kernel sr6 netdev.
	nh->vrf_id = vrf_frr_to_grout(VRF_DEFAULT);

	sr6->encap_behavior = mode == SR6_ENCAP_MODE_REDUCED ? SR_H_ENCAPS_RED : SR_H_ENCAPS;
	memcpy(&sr6->seglist[0], sid, sizeof(sr6->seglist[0]));
	sr6->n_seglist = 1;
}

static enum zebra_dplane_result sr6_l2encap_nh_add(const struct in6_addr *sid, uint8_t mode) {
	struct gr_nh_add_req *req;
	size_t len;
	int ret;

	len = sizeof(*req) + sizeof(struct gr_nexthop_info_srv6) + sizeof(struct rte_ipv6_addr);
	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req->exist_ok = true;
	sr6_l2encap_nh_fill(&req->nh, sid, mode);

	ret = grout_client_send_recv(GR_NH_ADD, len, req, NULL);
	free(req);

	return ret == 0 ? ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE;
}

static enum zebra_dplane_result sr6_l2encap_nh_del(const struct in6_addr *sid, uint8_t mode) {
	struct gr_nh_del_req *req;
	size_t len;
	int ret;

	// GR_NH_DEL matches by nexthop key: the request must carry the same
	// segment list that was programmed.
	len = sizeof(*req) + sizeof(struct gr_nexthop_info_srv6) + sizeof(struct rte_ipv6_addr);
	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req->missing_ok = true;
	sr6_l2encap_nh_fill(&req->nh, sid, mode);

	ret = grout_client_send_recv(GR_NH_DEL, len, req, NULL);
	free(req);

	return ret == 0 ? ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE;
}

// Delete the encap nexthop of @port unless another port still references
// the same segment list (nexthops are keyed by segment, not by port).
static void sr6_l2encap_release(const struct sr6_port *port) {
	struct sr6_port *other;

	frr_each (sr6_port_hash, &sr6_ports, other) {
		if (other == port)
			continue;
		if (other->mode == port->mode
		    && memcmp(&other->sid, &port->sid, sizeof(other->sid)) == 0)
			return;
	}

	sr6_l2encap_nh_del(&port->sid, port->mode);
}

void grout_sr6_port_del(uint16_t iface_id) {
	struct sr6_port *port = sr6_port_lookup(iface_id);

	if (port == NULL)
		return;

	if (!IN6_IS_ADDR_UNSPECIFIED(&port->sid))
		sr6_l2encap_release(port);

	sr6_port_hash_del(&sr6_ports, port);
	XFREE(MTYPE_GROUT_MEM, port);
}

// Mirror the kernel changelink IFLA_MTU part: apply the sr6 tunnel MTU to
// the grout interface standing in for the sr6 netdev.
static void sr6_port_set_mtu(uint16_t iface_id, uint32_t mtu) {
	struct gr_iface_set_req *req = calloc(1, sizeof(*req));

	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return;
	}

	req->set_attrs = GR_IFACE_SET_MTU;
	req->iface.base.id = iface_id;
	req->iface.base.mtu = mtu;

	grout_client_send_recv(GR_IFACE_SET, sizeof(*req), req, NULL);
	free(req);
}

// DPLANE_OP_SR6_UPDATE_SID ///////////////////////////////////////////////////

enum zebra_dplane_result grout_sr6_update_sid_ctx(struct zebra_dplane_ctx *ctx) {
	const struct in6_addr *sid = dplane_ctx_get_sr6_sid(ctx);
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	uint32_t mtu = dplane_ctx_get_ifp_mtu(ctx);
	uint16_t iface_id = ifindex_frr_to_grout(ifindex);
	enum zebra_dplane_result ret = ZEBRA_DPLANE_REQUEST_SUCCESS;
	uint8_t mode = dplane_ctx_get_sr6_mode_present(ctx) ? dplane_ctx_get_sr6_mode(ctx)
							    : SR6_ENCAP_MODE_FULL;
	struct sr6_port *port;
	bool reset = IN6_IS_ADDR_UNSPECIFIED(sid);

	gr_log_debug(
		"%s iface %u sid %pI6 mtu %u mode %s",
		reset ? "reset" : "program",
		ifindex,
		sid,
		mtu,
		mode == SR6_ENCAP_MODE_REDUCED ? "reduced" : "full"
	);

	if (iface_id == GR_IFACE_ID_UNDEF) {
		if (reset)
			return ZEBRA_DPLANE_REQUEST_SUCCESS;
		gr_log_err("iface %u has no grout mapping", ifindex);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	port = sr6_port_lookup(iface_id);
	if (port == NULL) {
		if (reset)
			return ZEBRA_DPLANE_REQUEST_SUCCESS;
		port = XCALLOC(MTYPE_GROUT_MEM, sizeof(*port));
		port->iface_id = iface_id;
		sr6_port_hash_add(&sr6_ports, port);
	}

	// Release the previous segment when it changes: SRv6 output nexthops
	// are keyed by segment list, so adding the new one would leave the old
	// one behind (the kernel changelink replaces the netdev SRH in place).
	if (!IN6_IS_ADDR_UNSPECIFIED(&port->sid)
	    && (reset || memcmp(&port->sid, sid, sizeof(port->sid)) != 0 || port->mode != mode))
		sr6_l2encap_release(port);

	if (reset) {
		memset(&port->sid, 0, sizeof(port->sid));
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	// Always (re)programmed, even when unchanged: idempotent refresh of
	// a nexthop lost to a grout restart (zebra re-issues the op when the
	// interface is re-added on reconnect).
	ret = sr6_l2encap_nh_add(sid, mode);
	if (ret != ZEBRA_DPLANE_REQUEST_SUCCESS)
		return ret;

	port->sid = *sid;
	port->mode = mode;

	if (mtu != 0)
		sr6_port_set_mtu(iface_id, mtu);

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

// DPLANE_OP_BRPORT_FLAGS /////////////////////////////////////////////////////

enum zebra_dplane_result grout_sr6_brport_flags_ctx(struct zebra_dplane_ctx *ctx) {
	bool is_bum = dplane_ctx_get_br_is_bum(ctx);
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	struct gr_iface_set_req *req;
	struct interface *ifp;
	size_t len;

	gr_log_debug("iface %u is_bum %u", ifindex, is_bum);

	/*
	 * The kernel op pushes an EVPN bridge-port profile onto the sr6 port:
	 * never learn (decapped frames carry remote MACs), flood only in the
	 * BUM role, always isolated (split horizon). grout bridges have no
	 * per-port learning/flood/isolation control, and learning of remote
	 * MACs is inherently off in the EVPN model anyway (remote MACs are
	 * installed as external FDB entries, never learned). Flooding is a
	 * bridge-level property (GR_BRIDGE_F_FLOOD).
	 *
	 * The one expressible part: when the op targets a VXLAN interface
	 * (the fork's legacy model keeps a traffic-less VNI anchor), turn
	 * its FDB learning off, mirroring the kernel "learning off".
	 */
	ifp = if_lookup_by_index(ifindex, dplane_ctx_get_vrf(ctx));
	if (ifp == NULL || !IS_ZEBRA_IF_VXLAN(ifp))
		return ZEBRA_DPLANE_REQUEST_SUCCESS;

	len = sizeof(*req) + sizeof(struct gr_iface_info_vxlan);
	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req->set_attrs = GR_VXLAN_SET_FLAGS;
	req->iface.base.id = ifindex_frr_to_grout(ifindex);
	req->iface.base.type = GR_IFACE_TYPE_VXLAN;
	// GR_VXLAN_F_LEARN is the only vxlan flag: zeroed flags disable the
	// dynamic FDB learning of the bridged anchor.

	if (grout_client_send_recv(GR_IFACE_SET, len, req, NULL) < 0) {
		free(req);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	free(req);
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

// DPLANE_OP_BRIDGE_VLAN_ADD //////////////////////////////////////////////////

enum zebra_dplane_result grout_sr6_bridge_vlan_add_ctx(struct zebra_dplane_ctx *ctx) {
	gr_log_debug(
		"iface %u vid %u untagged %u pvid %u",
		dplane_ctx_get_ifindex(ctx),
		dplane_ctx_get_br_vid(ctx),
		dplane_ctx_get_br_untagged(ctx),
		dplane_ctx_get_br_pvid(ctx)
	);

	/*
	 * The kernel op binds the EVI VLAN onto the sr6 bridge port (AF_BRIDGE
	 * vlan membership). grout bridges are not VLAN-aware: there is no
	 * per-port VLAN filtering, so there is nothing to program. The vlan id
	 * is honored where it matters: the MAC install path programs remote
	 * MAC FDB entries with the same vlan id (grout FDB entries are keyed
	 * by (bridge, mac, vlan)).
	 */
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

#endif // HAVE_FRR_SRV6_L2EVPN
