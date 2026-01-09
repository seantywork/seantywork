#!/bin/bash



sudo ip netns add net0

sudo ip link add dev veth01 type veth peer name veth02 netns net0

sudo ip link set dev veth01 address 'aa:aa:aa:01:01:01'

sudo ip netns exec net0 ip link set dev veth02 address 'aa:aa:aa:02:02:02'

sudo ip link set up veth01

sudo ip netns exec net0 ip link set up veth02

sudo ip addr add 192.168.10.1/24 dev veth01

sudo ip netns exec net0 ip addr add 192.168.10.2/24 dev veth02
