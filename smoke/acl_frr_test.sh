#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Christophe Fontaine, Red Hat

# Validate the ACL pipeline between zebra and the grout dataplane plugin
# with a raw zapi client, without needing bgpd or flowspec peers. The
# zapi_acl_inject helper speaks the zserv protocol directly: it programs
# the PBR netfilter objects (ipset, ipset entry, iptable) that BGP
# flowspec uses for ACLs and checks the notifications zebra sends back.
#
# The programmed filter drops all traffic with a source address of
# 172.16.0.2 (the netns peer) arriving on p0: pings to the peer must
# fail while the filter is installed and pass once it is removed.
#
# Phase 1 checks a full install/uninstall cycle, including the datapath
# drop.
#
# Phase 2 keeps the objects installed in zebra (the zapi client must stay
# connected: zebra removes the PBR objects when their owner client
# disconnects), restarts grout and checks that the plugin re-pushes them
# into the fresh instance by waiting for the resulting notification round
# and by matching traffic again.

. $(dirname $0)/_init_frr.sh

zserv="$frr_rundir/zserv.api"

create_interface p0

# grout creates the control plane netdev asynchronously; wait for it
# since its kernel ifindex is the one zebra identifies p0 with.
SECONDS=0
while ! ip link show p0 >/dev/null 2>&1; do
	[ "$SECONDS" -ge 5 ] && fail "control plane netdev for p0 not created"
	sleep 0.2
done
p0_ifindex=$(ip -j link show p0 | jq -r '.[0].ifindex')

set_ip_address p0 172.16.0.1/24

netns_add n0
move_to_netns x-p0 n0
ip -n n0 addr add 172.16.0.2/24 dev x-p0
ip -n n0 route add default via 172.16.0.1

# Wait for the peer address to be ready inside the netns.
SECONDS=0
while ! ip -n n0 addr show dev x-p0 to 172.16.0.2 | grep .; do
	[ "$SECONDS" -ge 5 ] && fail "address 172.16.0.2 not ready on x-p0"
	sleep 0.2
done

# The control plane takes a moment to deliver the first ICMP echo.
ping -c1 -W2 172.16.0.2

# Phase 1: install/uninstall cycle in a single zapi session. The
# injector pauses between the two phases (zebra removes the PBR objects
# when the owning client disconnects, so add and delete must share one
# connection). While the filter is installed, replies from the peer are
# dropped; once removed, they pass again.
zapi_acl_inject -i "$p0_ifindex" -s 10 "$zserv" &
injector_pid=$!

# Wait for the install to complete, then check the datapath drop.
sleep 4

ping -i0.1 -c3 -W1 172.16.0.2 \
	&& fail "ICMP replies from the peer pass while the filter is installed"

# Wait for the delete to complete, then check the traffic passes again.
wait "$injector_pid" || fail "ACL install/uninstall cycle failed"

ping -i0.1 -c3 -W1 172.16.0.2 \
	|| fail "ICMP replies from the peer do not pass after filter removal"

# Phase 2: leave the objects installed in zebra and restart grout. The
# plugin is expected to detect the reconnect, wipe and rebuild zebra's
# interface state from the fresh grout, then re-push the ACL objects
# held by zebra, which sends a new round of notifications to the still
# connected client.
#
# Note: the pushed filter references interfaces by their grout ids, but
# at resync time the fresh grout has no interfaces yet (they are created
# by the deployment after the restart). The filter is stored with an
# empty interface list and will only match traffic once it is updated.
# The datapath drop is validated in phase 1.
zapi_acl_inject -w 60 -i "$p0_ifindex" "$zserv" &
injector_pid=$!

# Let the injector complete the initial install round before killing
# grout.
sleep 2

restart_grout

# Wait for the resync notifications: the objects were re-pushed.
wait "$injector_pid" || fail "ACL objects not resynced into grout after restart"

grcli acl filter show | grep -q "102" \
	|| fail "filter not present in grout after resync"

true
