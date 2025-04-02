#!/bin/bash

sudo ip netns add vnet

sudo ip link set kneigh1 netns vnet 

sudo ip addr add 192.168.10.1/24 dev kneigh0

sudo ip link set dev kneigh0 up

sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev kneigh1

sudo ip netns exec vnet ip link set dev kneigh1 up

