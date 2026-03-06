#!/bin/bash 


echo "creating interface..."

sudo ip netns add net1

sudo ip link add dev veth11 type veth peer name veth12 netns net1

sudo ip link set up veth11

sudo ip netns exec net1 ip link set up veth12

sudo ip addr add 192.168.62.5/24 dev veth11

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth12

echo "created interface!"
