#!/bin/bash


sudo ip link set dev kxdp0 down

sudo ip netns exec vnet ip link set dev kxdp1 down

sudo ip addr del 192.168.10.1/24 dev kxdp0

sudo ip netns exec vnet ip addr del 192.168.10.2/24 dev kxdp1

sudo ip netns del vnet




