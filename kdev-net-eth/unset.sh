#!/bin/bash


sudo ip link set dev deth0 down

sudo ip netns exec vnet ip link set dev deth1 down

sudo ip addr del 192.168.10.1/24 dev deth0

sudo ip netns exec vnet ip addr del 192.168.10.2/24 dev deth1

sudo ip netns del vnet




