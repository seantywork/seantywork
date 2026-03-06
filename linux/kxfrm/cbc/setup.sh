#!/bin/bash

sudo ip netns add vnet

sudo ip link set kxfrm1 netns vnet 
sudo ip addr add 192.168.10.1/24 dev kxfrm0
sudo ip addr add 10.168.66.1/24 dev kxfrm0
sudo ip link set dev kxfrm0 up
sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev kxfrm1
sudo ip netns exec vnet ip addr add 10.168.66.2/24 dev kxfrm1
sudo ip netns exec vnet ip link set dev kxfrm1 up

#sudo ip link add dev veth01 type veth peer name veth02 netns vnet
#sudo ip addr add 192.168.10.1/24 dev veth01
#sudo ip addr add 10.168.66.1/24 dev veth01
#sudo ip link set up veth01
#sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev veth02
#sudo ip netns exec vnet ip addr add 10.168.66.2/24 dev veth02
#sudo ip netns exec vnet ip link set up veth02