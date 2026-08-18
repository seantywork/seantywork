#!/bin/bash

sudo ip netns add vnet

sudo ip link set dummveth1 netns vnet 

sudo ip addr add 192.168.10.1/24 dev dummveth0

sudo ip link set dev dummveth0 up

sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev dummveth1

sudo ip netns exec vnet ip link set dev dummveth1 up

