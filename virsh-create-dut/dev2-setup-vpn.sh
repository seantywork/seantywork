#!/bin/bash


sudo ip netns add vnet2

sudo ip link set enp7s0 netns vnet2

sudo ip netns exec vnet2 ip link set up enp7s0

sudo ip netns exec vnet2 ip addr add 10.168.0.29/24 dev enp7s0

sudo ip netns exec vnet2 ip route default via 10.168.0.26