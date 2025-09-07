#!/bin/bash

sudo ip netns add vnet

sudo ip link set kxdp1 netns vnet 

sudo ip addr add 192.168.10.1/24 dev kxdp0

sudo ip link set dev kxdp0 up

sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev kxdp1

sudo ip netns exec vnet ip link set dev kxdp1 up

