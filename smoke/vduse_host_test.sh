#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine

# Exercise a host-mode VDUSE port end to end:
#   grcli interface add vduse <name>
#     -> DPDK net_vhost creates /dev/vduse/<name>
#     -> grout instantiates the vdpa device and binds virtio_vdpa
#     -> the host kernel virtio-net netdev is renamed to "dp-<name>"
#     -> the control plane TAP keeps the interface name "<name>"
# The datapath frontend (dp-<name>) is moved to a separate netns so that traffic
# has to cross the vhost/vduse boundary to reach grout, then we ping grout's
# address on the port through it.
#
# The kernel vdpa generic-netlink family is only exposed in the initial network
# namespace. Rather than running grout there, this exercises the isolated
# deployment: grout runs in the unshared netns the harness creates for every
# test, and GROUT_VDPA_NETNS points it at a bind-mounted reference to the initial
# netns (/run/netns/host, set up by _init.sh) so it can enter it for vdpa
# operations. In host mode grout then moves the peer netdev back into its own
# netns, where the control plane TAP also lives.
export GROUT_VDPA_NETNS=/run/netns/host

. $(dirname $0)/_init.sh

# 125 is mapped to SKIPPED by the smoke test runner (GNUmakefile).
skip() { echo "SKIP: $*" >&2; exit 125; }

# VDUSE relies on host kernel modules that are not namespaced. They must be
# available (and loadable) for this test to run; otherwise skip, do not fail.
modprobe vduse || skip "cannot load the 'vduse' kernel module"
modprobe virtio-vdpa || skip "cannot load the 'virtio_vdpa' kernel module"
[ -d /sys/class/vduse ] || skip "vduse not available (missing CONFIG_VDPA_USER?)"

name=vduse0
dp_name="dp-$name"

# Best effort cleanup of anything a previous aborted run may have left behind:
# the vduse device and vdpa device are global (not netns scoped), but the vdpa
# netlink family is only reachable from the initial netns (/run/netns/host).
if command -v vdpa >/dev/null; then
	ip netns exec host vdpa dev del "$name" 2>/dev/null || :
fi

# The vdpa/vduse device is global (not netns scoped) and grout normally removes
# it on "interface del". Register a fallback teardown so it does not leak into
# the host if grout dies before it can run its own cleanup.
cat >> "$tmp/cleanup" <<EOF
command -v vdpa >/dev/null && ip netns exec host vdpa dev del "$name" 2>/dev/null || true
EOF

grcli interface add vduse "$name"
grcli address add 172.16.0.1/24 iface "$name"
grcli address add fd00:ba4::1/64 iface "$name"

# grout runs in the unshared netns, so its control plane TAP lives there. The
# control plane TAP keeps the interface name like every other interface; the
# datapath netdev (the peer virtio-net device) is created by virtio_vdpa in the
# initial netns, moved by grout into its own (unshared) netns, and renamed to
# "dp-<name>" to avoid a collision.
SECONDS=0
while ! ip link show "$name" >/dev/null 2>&1; do
	[ "$SECONDS" -gt 5 ] && fail "control plane tap $name not created"
	sleep 0.2
done
SECONDS=0
while ! ip link show "$dp_name" >/dev/null 2>&1; do
	[ "$SECONDS" -gt 5 ] && fail "datapath netdev $dp_name not moved into grout's netns"
	sleep 0.2
done

# Sanity: grcli must report the interface as a net_vhost port backed by a
# VDUSE device. (Host mode specifically is already proven by the datapath
# netdev above: only host mode creates and renames it.)
grcli -j interface show | jq -e \
	--arg n "$name" '.[] | select(.name == $n)
		| .info | test("iface=/dev/vduse/")' \
	|| fail "$name not reported as a vduse-backed port"

# Move the datapath frontend into its own netns, away from grout's control
# plane tap, so the ping really traverses the vduse datapath.
netns_add n0
ip link set "$dp_name" netns n0
ip -n n0 link set "$dp_name" up
ip -n n0 addr add 172.16.0.2/24 dev "$dp_name"
ip -n n0 addr add fd00:ba4::2/64 dev "$dp_name"

SECONDS=0
while ! ip -n n0 link show "$dp_name" | grep -qw LOWER_UP; do
	[ "$SECONDS" -gt 5 ] && fail "$dp_name link was not LOWER_UP after 5 seconds"
	sleep 0.2
done

ip netns exec n0 ping -i0.01 -c3 -n 172.16.0.1
ip netns exec n0 ping -i0.01 -c3 -n fd00:ba4::1
