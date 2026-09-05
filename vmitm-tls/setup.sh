#!/bin/bash 


sudo ip netns add net1

sudo ip netns add net2

sudo ip link add dev veth11 type veth peer name veth12 netns net1

sudo ip link add dev veth21 type veth peer name veth22 netns net2

sudo ip link set up veth11

sudo ip link set up veth21

sudo ip netns exec net1 ip link set up veth12

sudo ip netns exec net2 ip link set up veth22

sudo ip addr add 192.168.62.5/24 dev veth11

sudo ip addr add 192.168.64.5/24 dev veth21

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth12

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth12 

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth22 

sudo ip netns exec net2 ip route add default via 192.168.64.5 dev veth22