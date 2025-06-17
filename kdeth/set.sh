#!/bin/bash

sudo ip netns add vnet

sudo ip link set deth1 netns vnet 

sudo ip addr add 192.168.10.1/24 dev deth0

sudo ip link set dev deth0 up

sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev deth1

sudo ip netns exec vnet ip link set dev deth1 up

