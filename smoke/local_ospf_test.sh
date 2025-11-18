#!/bin/bash
. $(dirname $0)/_init_frr.sh


ip link add vA type veth peer vB

start_frr_on_namespace ospf1
start_frr_on_namespace ospf2

ip link set vA netns ospf1
ip link set vB netns ospf2
ip -n ospf1 link set vA up
ip -n ospf2 link set vB up


ip netns exec ospf1 tcpdump -veni vA -c 1000 -w ospf1-vA.pcap &
ip netns exec ospf2 tcpdump -veni vB &

vtysh -N ospf1 <<-EOF
configure terminal
ipv6 router-id 172.16.0.1
!
ipv6 forwarding
!
debug ospf6 event
debug ospf6 message all
debug ospf event
debug ospf packet all
!
interface lo
	ip address 17.0.0.1/24
exit
!
interface vA
	ipv6 ospf6 area 0.0.0.1
exit
!
router ospf
	ospf router-id 172.16.0.1
	network 172.16.0.0/24 area 10.0.0.1
	network 17.0.0.0/24 area 10.0.0.1
exit
router ospf6
	ospf6 router-id 172.16.0.1
	area 0.0.0.1 range 2001:db8:2000::/48
exit
end
!
EOF

vtysh -N ospf2 <<-EOF
configure terminal
ipv6 router-id 172.16.0.2
!
ipv6 forwarding
!
debug ospf6 event
debug ospf6 message all
interface lo
	ip address 16.0.0.1/24
exit
!
interface vB
	ipv6 ospf6 area 0.0.0.1
exit
!
router ospf
	ospf router-id 172.16.0.2
	network 172.16.0.0/24 area 10.0.0.1
	network 16.0.0.0/24 area 10.0.0.1
exit
router ospf6
	ospf6 router-id 172.16.0.2
	area 0.0.0.1 range 2001:db8:2000::/48
exit
end
!
EOF
