#!/bin/bash

set -exo pipefail

sudo modprobe br_netfilter

sudo ip netns add net1
sudo ip netns add net2
sudo ip link add dev veth1 type veth peer name veth2 netns net1
sudo ip netns exec net1 ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link add br0 type bridge stp_state 0
sudo ip link set ens3 master br0
sudo ip link set veth1 master br0
sudo ip addr add 192.168.101.25/24 dev br0
sudo ip addr add 10.168.0.254/24 dev br0

sudo ip netns exec net1 ip link add br1 type bridge stp_state 1
sudo ip netns exec net1 ip link set veth2 master br1
sudo ip netns exec net1 ip link set veth3 master br1
sudo ip netns exec net1 ip addr add 10.168.0.1/24 dev br1

sudo ip netns exec net2 ip addr add 10.168.0.2/24 dev veth4

sudo ip link set up ens3
sudo ip link set up veth1 
sudo ip link set up br0
sudo ip route add default via 192.168.101.1 dev br0
sudo sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec net1 ip link set up lo
sudo ip netns exec net1 ip link set up veth2 
sudo ip netns exec net1 ip link set up veth3
sudo ip netns exec net1 ip link set up br1
sudo ip netns exec net1 ip route add default via 10.168.0.254 dev br1
sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec net2 ip link set up lo
sudo ip netns exec net2 ip link set up veth4
sudo ip netns exec net2 ip route add default via 10.168.0.1 dev veth4
sudo ip netns exec net2 sysctl -w net.ipv4.ip_forward=1
