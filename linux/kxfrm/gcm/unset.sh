#!/bin/bash

sudo ip netns del vnet

sudo ip xfrm state flush

sudo ip xfrm policy flush

#sudo ip link add dev veth01 type veth peer name veth02 netns vnet
#sudo ip addr add 192.168.10.1/24 dev veth01
#sudo ip addr add 10.168.66.1/24 dev veth01
#sudo ip link set up veth01
#sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev veth02
#sudo ip netns exec vnet ip addr add 10.168.66.2/24 dev veth02
#sudo ip netns exec vnet ip link set up veth02