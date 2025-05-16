#!/bin/bash


sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.64.1/24 dev veth1

sudo ip route add 192.168.64.0/24 via 192.168.64.2 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.1 dev veth4

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 ip link add br0 type bridge stp_state 0

sudo ip netns exec net1 ip link set br0 address 12:34:56:78:9a:bc

sudo ip netns exec net1 ip link set veth2 master br0 

sudo ip netns exec net1 ip link set veth3 master br0

sudo ip netns exec net1 ip addr add 192.168.64.2/24 dev br0

sudo ip netns exec net1 ip link set br0 up

sudo ip netns exec net1 ip link set veth2 up 

sudo ip netns exec net1 ip link set veth3 up

sudo ip netns exec net1 ip route add default via 192.168.64.1 dev br0

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.2 dev br0 proto static

sudo iptables -t nat -I POSTROUTING -p all -o br0 -j MASQUERADE
