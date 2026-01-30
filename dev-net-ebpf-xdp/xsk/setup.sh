#!/bin/bash



sudo ip netns add vnet0

sudo ip link add dev veth01 type veth peer name veth02 netns vnet0

sudo ip link set up veth01

sudo ip netns exec vnet0 ip link set up veth02

sudo ip addr add 192.168.33.1/24 dev veth01

sudo ip netns exec vnet0 ip addr add 192.168.33.5/24 dev veth02

sudo ip netns exec vnet0 ip route add 192.168.66.0/24 via 192.168.33.1

sudo ip netns exec vnet0 ip link set lo up

sudo ip netns add vnet1

sudo ip link add dev veth11 type veth peer name veth12 netns vnet1

sudo ip link set up veth11

sudo ip netns exec vnet1 ip link set up veth12

sudo ip addr add 192.168.66.1/24 dev veth11

sudo ip netns exec vnet1 ip addr add 192.168.66.5/24 dev veth12

sudo ip netns exec vnet1 ip route add 192.168.33.0/24 via 192.168.66.1

sudo ip netns exec vnet1 ip link set lo up

sudo sysctl -w net.ipv4.ip_forward=1

sudo ethtool -L veth01 rx 4

sudo ethtool -L veth01 tx 4

sudo ethtool -L veth11 rx 4

sudo ethtool -L veth11 tx 4