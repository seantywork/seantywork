#!/bin/bash 

set -x

#sudo ip netns add vb1

sudo ip netns add v1

#sudo ip link add dev wgeth1 type veth peer name veth01 netns vb1

sudo ip link add dev wgeth1 type veth peer name wgeth2 netns v1

#sudo ip netns exec vb1 ip link add dev veth02 type veth peer name wgeth2 netns v1

sudo ip netns exec v1 ip link set up wgeth2

sudo ip netns exec v1 ip addr add 10.14.0.250/24 dev wgeth2

sudo ip netns exec v1 ip route add default via 10.14.0.25 dev wgeth2

sudo ip netns exec v1 ip link set up lo

sudo ip addr add 10.14.0.25/24 dev wgeth1

sudo ip link set up wgeth1

#sudo ip netns exec vb1 ip link add netbr0 type bridge stp_state 1

#sudo ip netns exec vb1 ip link set veth01 master netbr0 

#sudo ip netns exec vb1 ip link set veth02 master netbr0 

#sudo ip netns exec vb1 ip link set lo up

#sudo ip netns exec vb1 ip link set veth01 up 

#sudo ip netns exec vb1 ip link set veth02 up 

#sudo ip netns exec vb1 ip link set netbr0 up 

#sudo ip netns exec vb1 sysctl -w net.ipv4.ip_forward=1
