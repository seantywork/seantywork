#!/bin/bash

set -x

sudo ip netns add vnet0

sudo ip netns add vnet1
sudo ip netns exec vnet0 ip link add dev veth11 type veth peer name veth12 netns vnet1
sudo ip netns exec vnet1 ip link set up veth12
sudo ip netns exec vnet1 ip addr add 192.168.33.5/24 dev veth12
sudo ip netns exec vnet1 ip route add default dev veth12
sudo ip netns exec vnet1 ip link set lo up

sudo ip netns add vnet2
sudo ip netns exec vnet0 ip link add dev veth21 type veth peer name veth22 netns vnet2
sudo ip netns exec vnet2 ip link set up veth22
sudo ip netns exec vnet2 ip addr add 192.168.66.5/24 dev veth22
sudo ip netns exec vnet2 ip route add default dev veth22
sudo ip netns exec vnet2 ip link set lo up

sudo ip netns exec vnet0 ip link add vbr0 type bridge stp_state 0
sudo ip netns exec vnet0 ip link set veth11 master vbr0
sudo ip netns exec vnet0 ip link set veth21 master vbr0
sudo ip netns exec vnet0 ip link set up veth11
sudo ip netns exec vnet0 ip link set up veth21
sudo ip netns exec vnet0 ip link set up vbr0
sudo ip netns exec vnet0 ip addr add 10.10.10.10/32 dev vbr0
sudo ip netns exec vnet0 ip route add default dev vbr0
sudo ip netns exec vnet0 ip link set up lo

sudo ip netns exec vnet0 sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec vnet0 ethtool -L veth11 rx 8
sudo ip netns exec vnet0 ethtool -L veth11 tx 8
sudo ip netns exec vnet0 ethtool -L veth21 rx 8
sudo ip netns exec vnet0 ethtool -L veth21 tx 8