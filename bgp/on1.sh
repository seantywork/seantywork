#!/bin/bash

sudo sysctl -w net.ipv4.ip_forward=1

sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip addr add 10.0.11.1/24 dev veth1

sudo ip netns exec net1 ip addr add 10.0.11.2/24 dev veth2

sudo ip netns exec net1 ip route add default via 10.0.11.1 dev veth2