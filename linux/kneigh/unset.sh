#!/bin/bash


sudo ip link set dev kneigh0 down

sudo ip netns exec vnet ip link set dev kneigh1 down

sudo ip addr del 192.168.10.1/24 dev kneigh0

sudo ip netns exec vnet ip addr del 192.168.10.2/24 dev kneigh1

sudo ip netns del vnet




