#!/bin/bash

sudo ip link add br0 type bridge 

sudo ip link set br0 type bridge stp_state 1


sudo ip netns add vnet0

sudo ip link add dev veth01 type veth peer name veth02 netns vnet0

sudo ip link set up veth01

sudo ip netns exec vnet0 ip link set up veth02

sudo ip netns exec vnet0 ip addr add 10.168.0.1/24 dev veth02

sudo ip netns add vnet1

sudo ip link add dev veth11 type veth peer name veth12 netns vnet1

sudo ip link set up veth11

sudo ip netns exec vnet1 ip link set up veth12

sudo ip netns exec vnet1 ip addr add 10.168.0.2/24 dev veth12

sudo ip netns add vnet2

sudo ip link add dev veth21 type veth peer name veth22 netns vnet2

sudo ip link set up veth21

sudo ip netns exec vnet2 ip link set up veth22

sudo ip netns exec vnet2 ip addr add 10.168.0.200/24 dev veth22


sudo ip link set veth01 master br0

sudo ip link set veth11 master br0

sudo ip link set veth21 master br0

sudo ip link set br0 up