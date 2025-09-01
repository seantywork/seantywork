#!/bin/bash

sudo ip netns add vnet0

sudo ip link add dev veth01 type veth peer name veth02 netns vnet0

sudo ip link set up veth01

sudo ip addr add 11.168.0.1/24 dev veth01


sudo ip netns add vnet1

sudo ip netns exec vnet0 ip link add dev veth12 type veth peer name veth11 netns vnet1

sudo ip netns exec vnet1 ip link set up veth11

sudo ip netns exec vnet1 ip addr add 11.168.0.2/24 dev veth11

sudo ip netns add vnet2

sudo ip netns exec vnet0 ip link add dev veth22 type veth peer name veth21 netns vnet2

sudo ip netns exec vnet2 ip link set up veth21

sudo ip netns exec vnet2 ip addr add 11.168.0.200/24 dev veth21


sudo ip netns exec vnet0 ip link add vbr0 type bridge 

sudo ip netns exec vnet0 ip link set vbr0 type bridge stp_state 1

sudo ip netns exec vnet0 ip link set veth02 master vbr0

sudo ip netns exec vnet0 ip link set veth12 master vbr0

sudo ip netns exec vnet0 ip link set veth22 master vbr0

sudo ip netns exec vnet0 ip link set veth02 up

sudo ip netns exec vnet0 ip link set veth12 up

sudo ip netns exec vnet0 ip link set veth22 up

sudo ip netns exec vnet0 ip link set vbr0 up


sudo ip netns exec vnet0 /bin/bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo ip netns exec vnet0 /bin/bash -c "echo 1 > /proc/sys/net/ipv4/conf/vbr0/arp_accept"
sudo ip netns exec vnet0 /bin/bash -c "echo 1 > /proc/sys/net/ipv4/conf/veth02/arp_accept"
sudo ip netns exec vnet0 /bin/bash -c "echo 1 > /proc/sys/net/ipv4/conf/veth12/arp_accept"
sudo ip netns exec vnet0 /bin/bash -c "echo 1 > /proc/sys/net/ipv4/conf/veth22/arp_accept"