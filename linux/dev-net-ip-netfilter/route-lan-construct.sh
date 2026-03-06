#!/bin/bash


sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2


sudo ip netns add net2

sudo ip link add dev veth21 type veth peer name veth22 netns net2

sudo ip link set up veth21

sudo ip netns exec net2 ip link set up veth22

sudo ip addr add 192.168.26.5/24 dev veth21

sudo ip netns exec net2 ip addr add 192.168.26.6/24 dev veth22

sudo sysctl -w net.ipv4.ip_forward=1

sudo iptables -P FORWARD ACCEPT

sudo ip netns exec net1 ip route add 192.168.26.0/24 via 192.168.62.5 dev veth2

sudo ip netns exec net2 ip route add 192.168.62.0/24 via 192.168.26.5 dev veth22