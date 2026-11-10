// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christophe Fontaine, Red Hat

// SRv6 L2 EVPN (RFC 9252) dataplane operations, from the FRR fork carrying
// FRRouting PR #22570 (based on FRR 10.9; the operations do not exist in
// earlier FRR releases). The content of this file is gated on the FRR
// version, like the other version-specific features.
//
// Model mapping (kernel -> grout):
//
// The fork expects operator-created "sr6" tunnel netdevs ("sr6-<n>"
// unicast End.DT2U, "bum-sr6-<n>" BUM End.DT2M, "vpws-sr6-<name>"
// End.DX2) enslaved to an EVPN bridge. Zebra discovers them by name on
// the bridge and reprograms them in place through the new dataplane ops.
// The grout counterpart is the GR_IFACE_TYPE_SR6 interface: the operator
// creates it as a bridge member (grcli "interface add sr6 NAME domain
// BRIDGE"), the plugin reports it to zebra with its name and bridge
// enslavement, and the ops translate to in-place reconfigurations of
// that interface:
//
// - DPLANE_OP_SR6_UPDATE_SID sets the *encap* segment of the tunnel port
//   (the remote PE SID; the all-zero SID resets the port). Translated to
//   the interface remote SID and encap mode (full/reduced); the MTU
//   carried by the op is applied to the interface, mirroring the kernel
//   changelink. Frames the bridge forwards to the port are encapsulated
//   toward the remote SID by the srv6_l2_output node.
//
// - DPLANE_OP_BRPORT_FLAGS pushes an EVPN bridge-port profile onto the
//   tunnel port: never learn, flood only in the BUM role, always
//   isolated. Translated to the SRv6 port flood flag: only BUM-role
//   ports receive bridge floods (the unicast-role port is reachable only
//   through FDB entries), and the bridge never learns from SRv6 ports.
//
// - DPLANE_OP_BRIDGE_VLAN_ADD binds an EVI VLAN onto the tunnel port.
//   Translated to the SRv6 port vlan: it is the FDB vlan used for the
//   frames decapsulated at the local End.DT2U/DT2M SIDs.
//
// The local End.DX2/DT2U/DT2M decap SIDs are not programmed through
// these ops: the fork's bgpd installs them as regular IPv6 /128 routes
// carrying a seg6local nexthop (see rt_grout.c for the translation, and
// the "seg6local nexthops are not installed separately" note in the
// grout-frr(7) manual page).

#include <lib/libfrr.h>

#if CURRENT_FRR_VERSION >= MAKE_FRRVERSION(10, 9, 0)

#include "if_map.h"
#include "log_grout.h"
#include "sr6_grout.h"

#include <gr_infra.h>
#include <gr_l2.h>
#include <gr_srv6.h>

#include <zebra/interface.h>

#include "zebra_dplane_grout.h"

// Encap-mode values of the fork's enum zebra_sr6_encap_mode (zebra_sr6.h
// is not exported to plugins): FULL keeps the SRH on the wire, REDUCED is
// the single-SID H.Encaps.L2.Red flavor (SID in the IPv6 DA, no SRH).
#define SR6_ENCAP_MODE_FULL 0
#define SR6_ENCAP_MODE_REDUCED 1

// The fork's sr6 tunnel ports are discovered by name: sr6-<n> (unicast),
// bum-sr6-<n> (BUM) and vpws-sr6-<name> (VPWS).
static bool is_sr6_iface_name(const char *name) {
	return strncmp(name, "sr6-", 4) == 0 || strncmp(name, "bum-sr6-", 8) == 0
	       || strncmp(name, "vpws-sr6-", 9) == 0;
}

// Verify that the interface the FRR ifindex maps to is actually of the
// sr6 type in grout. The fork discovers the sr6 tunnel ports by NAME
// only: nothing guarantees that an interface named sr6-* is of the sr6
// type, and the type-specific reconfiguration attribute bits overlap the
// namespaces of the other interface types (GR_SR6_SET_VLAN is
// GR_PORT_SET_N_TXQS, GR_SR6_SET_SID is GR_PORT_SET_MAC, ...). Sending
// them to a mistyped interface would silently corrupt its configuration.
static bool sr6_iface_is_sr6_type(uint16_t iface_id) {
	struct gr_iface_get_resp *resp = NULL;
	struct gr_iface_get_req req = {.iface_id = iface_id};
	bool is_sr6;

	if (grout_client_send_recv(GR_IFACE_GET, sizeof(req), &req, (void **)&resp) < 0)
		return false;

	is_sr6 = resp->iface.base.type == GR_IFACE_TYPE_SR6;
	if (!is_sr6)
		// Give the callers a meaningful errno for the dplane context.
		errno = EMEDIUMTYPE;
	free(resp);
	return is_sr6;
}

// DPLANE_OP_SR6_UPDATE_SID /////////////////////////////////////////////////

enum zebra_dplane_result grout_sr6_update_sid_ctx(struct zebra_dplane_ctx *ctx) {
	const struct in6_addr *sid = dplane_ctx_get_sr6_sid(ctx);
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	uint32_t mtu = dplane_ctx_get_ifp_mtu(ctx);
	uint16_t iface_id = ifindex_frr_to_grout(ifindex);
	struct gr_iface_set_req *req;
	struct gr_iface_info_sr6 *info;
	uint8_t mode = dplane_ctx_get_sr6_mode_present(ctx) ? dplane_ctx_get_sr6_mode(ctx)
							    : SR6_ENCAP_MODE_FULL;
	bool reset = IN6_IS_ADDR_UNSPECIFIED(sid);
	size_t len;
	int ret;

	gr_log_debug(
		"%s iface %u sid %pI6 mtu %u mode %s",
		reset ? "reset" : "program",
		ifindex,
		sid,
		mtu,
		mode == SR6_ENCAP_MODE_REDUCED ? "reduced" : "full"
	);

	if (iface_id == GR_IFACE_ID_UNDEF) {
		// A missing mapping is transient (grout reconnect window).
		// Zebra does not retry dplane_sr6_program on a dplane failure,
		// but the op is re-issued when the interface is re-added on
		// reconnect (zebra_sr6_if_add) or on the next EVPN realize, so
		// failing here only delays the programming.
		if (reset)
			return ZEBRA_DPLANE_REQUEST_SUCCESS;
		gr_log_err("iface %u has no grout mapping", ifindex);
		errno = ENODEV;
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (!sr6_iface_is_sr6_type(iface_id)) {
		if (reset) {
			// Nothing was ever programmed on it: any program op
			// would have failed the same check.
			return ZEBRA_DPLANE_REQUEST_SUCCESS;
		}
		gr_log_err(
			"iface %u is not an sr6 interface (discovered by name only)", ifindex
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	// In-place reprogram of the SRv6 port: {remote SID, encap mode, MTU},
	// exactly the triplet the kernel changelink carries. The all-zero SID
	// disables the encapsulation.
	len = sizeof(*req) + sizeof(*info);
	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req->set_attrs = GR_SR6_SET_SID | GR_SR6_SET_ENCAP;
	if (mtu != 0)
		req->set_attrs |= GR_IFACE_SET_MTU;
	req->iface.base.id = iface_id;
	req->iface.base.type = GR_IFACE_TYPE_SR6;
	req->iface.base.mtu = mtu;

	info = (struct gr_iface_info_sr6 *)req->iface.info;
	memcpy(&info->remote_sid, sid, sizeof(info->remote_sid));
	info->encap = mode == SR6_ENCAP_MODE_REDUCED ? SR_H_ENCAPS_RED : SR_H_ENCAPS;

	ret = grout_client_send_recv(GR_IFACE_SET, len, req, NULL);
	free(req);

	return ret == 0 ? ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE;
}

// DPLANE_OP_BRPORT_FLAGS ///////////////////////////////////////////////////

enum zebra_dplane_result grout_sr6_brport_flags_ctx(struct zebra_dplane_ctx *ctx) {
	bool is_bum = dplane_ctx_get_br_is_bum(ctx);
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	struct gr_iface_set_req *req = NULL;
	struct interface *ifp;
	size_t len = 0;
	int ret;

	gr_log_debug("iface %u is_bum %u", ifindex, is_bum);

	/*
	 * The kernel op pushes an EVPN bridge-port profile onto the sr6 port:
	 * never learn, flood only in the BUM role, always isolated. grout
	 * never learns on SRv6 ports and isolation is inherent (floods never
	 * go back out of the decap injection port); the flood role is the
	 * port's FLOOD flag.
	 *
	 * The op is also used on the VXLAN interface anchoring a VNI in the
	 * fork's legacy model: translate the "learning off" part there.
	 *
	 * A missing FRR ifindex -> grout mapping (grout reconnect window)
	 * makes the sr6 type check fail and the op fall through to the name
	 * warning below: the flood flag is not programmed right away, but the
	 * op is re-issued when the interface is re-added on reconnect or on
	 * the next EVPN realize, like DPLANE_OP_SR6_UPDATE_SID, so the window
	 * only delays the programming.
	 */
	ifp = if_lookup_by_index(ifindex, dplane_ctx_get_vrf(ctx));
	if (ifp == NULL)
		return ZEBRA_DPLANE_REQUEST_SUCCESS;

	if (sr6_iface_is_sr6_type(ifindex_frr_to_grout(ifindex))) {
		len = sizeof(*req) + sizeof(struct gr_iface_info_sr6);
		req = calloc(1, len);
		if (req == NULL) {
			gr_log_err("calloc: %s", strerror(errno));
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		req->set_attrs = GR_SR6_SET_FLAGS;
		req->iface.base.id = ifindex_frr_to_grout(ifindex);
		req->iface.base.type = GR_IFACE_TYPE_SR6;
		((struct gr_iface_info_sr6 *)req->iface.info)->flags =
			is_bum ? GR_SR6_F_FLOOD : 0;
	} else if (IS_ZEBRA_IF_VXLAN(ifp)) {
		len = sizeof(*req) + sizeof(struct gr_iface_info_vxlan);
		req = calloc(1, len);
		if (req == NULL) {
			gr_log_err("calloc: %s", strerror(errno));
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		req->set_attrs = GR_VXLAN_SET_FLAGS;
		req->iface.base.id = ifindex_frr_to_grout(ifindex);
		req->iface.base.type = GR_IFACE_TYPE_VXLAN;
		// GR_VXLAN_F_LEARN is the only vxlan flag: zeroed flags
		// disable the dynamic FDB learning of the bridged anchor.
	} else {
		// Not an SRv6 port nor a VXLAN anchor: nothing to translate.
		// Warn on a name/type mismatch so operator mistakes surface.
		if (is_sr6_iface_name(ifp->name))
			gr_log_warn(
				"iface %s matches an sr6 port name but is not an sr6 interface",
				ifp->name
			);
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	ret = grout_client_send_recv(GR_IFACE_SET, len, req, NULL);
	free(req);

	return ret == 0 ? ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE;
}

// DPLANE_OP_BRIDGE_VLAN_ADD ////////////////////////////////////////////////

enum zebra_dplane_result grout_sr6_bridge_vlan_add_ctx(struct zebra_dplane_ctx *ctx) {
	vlanid_t vid = dplane_ctx_get_br_vid(ctx);
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	uint16_t iface_id = ifindex_frr_to_grout(ifindex);
	struct gr_iface_set_req *req;
	size_t len;
	int ret;

	gr_log_debug("iface %u vid %u", ifindex, vid);

	if (!sr6_iface_is_sr6_type(iface_id)) {
		gr_log_err(
			"iface %u is not an sr6 interface (discovered by name only)", ifindex
		);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	// The FDB vlan of the SRv6 port: decapsulated frames are looked up
	// and flooded with it (grout FDB entries are keyed by bridge, MAC and
	// vlan). The vlan id an EVPN control plane installs remote MAC FDB
	// entries with. Only sent to sr6 interfaces: the reconfiguration
	// attribute bits are per-type namespaces, another interface type
	// would reinterpret them as its own attributes.
	len = sizeof(*req) + sizeof(struct gr_iface_info_sr6);
	req = calloc(1, len);
	if (req == NULL) {
		gr_log_err("calloc: %s", strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	req->set_attrs = GR_SR6_SET_VLAN;
	req->iface.base.id = iface_id;
	req->iface.base.type = GR_IFACE_TYPE_SR6;
	((struct gr_iface_info_sr6 *)req->iface.info)->vlan_id = vid;

	ret = grout_client_send_recv(GR_IFACE_SET, len, req, NULL);
	free(req);

	return ret == 0 ? ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE;
}

#endif // FRR >= 10.9
