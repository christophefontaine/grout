#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine

. $(dirname $0)/_init.sh

echo "=== L2 Bridge Smoke Test ==="

# Create ports
port_add p0
port_add p1
port_add p2

# Create bridge domain
echo "Creating bridge domain..."
grcli bridge add testbr aging_time 300 max_mac_count 1024

# Get bridge ID (should be 1 for first bridge)
BRIDGE_ID=1

# Add interfaces to bridge
echo "Adding interfaces to bridge..."
grcli bridge member add $BRIDGE_ID p0
grcli bridge member add $BRIDGE_ID p1
grcli bridge member add $BRIDGE_ID p2

# Verify bridge configuration
echo "Bridge configuration:"
grcli bridge show $BRIDGE_ID

echo "Bridge members:"
grcli bridge member list $BRIDGE_ID

# Create bridge interface for L3 integration
echo "Creating bridge interface..."
grcli interface add bridge br1 bridge_id $BRIDGE_ID

# Assign IP address to bridge interface
echo "Assigning IP to bridge interface..."
grcli address add 192.168.100.1/24 iface br1

# Set up test namespaces connected to bridge ports
echo "Setting up test namespaces..."
for n in 0 1 2; do
	p=x-p$n
	ns=n$n
	netns_add $ns
	ip link set $p netns $ns
	ip -n $ns link set $p up
	ip -n $ns addr add 192.168.100.$((n+10))/24 dev $p
	ip -n $ns route add default via 192.168.100.1
done

read
# Wait a moment for interfaces to come up
sleep 2

echo "Testing L2 connectivity (same subnet)..."
# Test L2 connectivity between hosts in same bridge
ip netns exec n0 ping -i0.01 -c3 -W1 -n 192.168.100.11 || echo "L2 ping n0->n1 failed"
ip netns exec n1 ping -i0.01 -c3 -W1 -n 192.168.100.12 || echo "L2 ping n1->n2 failed"
ip netns exec n2 ping -i0.01 -c3 -W1 -n 192.168.100.10 || echo "L2 ping n2->n0 failed"

echo "Testing L3 connectivity (to bridge interface)..."
# Test L3 connectivity to bridge interface
ip netns exec n0 ping -i0.01 -c3 -W1 -n 192.168.100.1 || echo "L3 ping n0->bridge failed"
ip netns exec n1 ping -i0.01 -c3 -W1 -n 192.168.100.1 || echo "L3 ping n1->bridge failed"
ip netns exec n2 ping -i0.01 -c3 -W1 -n 192.168.100.1 || echo "L3 ping n2->bridge failed"

# Check MAC learning
echo "MAC table entries:"
grcli bridge mac list $BRIDGE_ID

# Test static MAC entry
echo "Adding static MAC entry..."
# Get MAC address of n0 interface
MAC0=$(ip netns exec n0 cat /sys/class/net/x-p0/address)
grcli bridge mac add $BRIDGE_ID $MAC0 p0 static

echo "MAC table after adding static entry:"
grcli bridge mac list $BRIDGE_ID

# Test MAC flush
echo "Flushing dynamic MAC entries..."
grcli bridge mac flush $BRIDGE_ID dynamic_only

echo "MAC table after flush:"
grcli bridge mac list $BRIDGE_ID

# Test bridge removal (cleanup)
echo "Cleaning up..."
grcli bridge member del $BRIDGE_ID p0
grcli bridge member del $BRIDGE_ID p1  
grcli bridge member del $BRIDGE_ID p2
grcli bridge del $BRIDGE_ID

echo "=== L2 Bridge Smoke Test Complete ==="
