#!/bin/bash


sudo ip netns add vnet0

sudo ip link add dev veth01 type veth peer name veth02 netns vnet0

sudo ip link set up veth01

sudo ip netns exec vnet0 ip link set up veth02

sudo ip addr add 11.168.0.1/24 dev veth01

sudo ip netns exec vnet0 ip addr add 11.168.0.2/24 dev veth02


