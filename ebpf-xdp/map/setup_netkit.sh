#!/bin/bash



sudo ip netns add vnet0

sudo ip link add nkpeer0 type netkit

sudo ip link set nkpeer0 netns vnet0

sudo ip link set dev nk0 up

sudo ip netns exec vnet0 ip link set dev nkpeer0 up

sudo ip addr add 192.168.33.1/24 dev nk0

sudo ip netns exec vnet0 ip addr add 192.168.33.5/24 dev nkpeer0







