#!/bin/bash


sudo ip link set dev dummveth0 down

sudo ip netns exec vnet ip link set dev dummveth1 down

sudo ip addr del 192.168.10.1/24 dev dummveth0

sudo ip netns exec vnet ip addr del 192.168.10.2/24 dev dummveth1

sudo ip netns del vnet




