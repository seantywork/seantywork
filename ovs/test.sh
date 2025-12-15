#!/bin/bash

set -exo pipefail

ovs_test(){
    sudo ovs-vsctl add-br ovs-br0
    sudo ip netns add net1
    sudo ip netns add net2
    sudo ip link add dev veth11 type veth peer name veth12 netns net1
    sudo ip link add dev veth21 type veth peer name veth22 netns net2
    sudo ovs-vsctl add-port ovs-br0 veth11
    sudo ovs-vsctl add-port ovs-br0 veth21
    sudo ip netns exec net1 ip addr add 192.168.64.12/24 dev veth12
    sudo ip netns exec net2 ip addr add 192.168.64.22/24 dev veth22
    sudo ip netns exec net1 ip link set veth12 up
    sudo ip netns exec net2 ip link set veth22 up
    sudo ip link set up veth11
    sudo ip link set up veth21
    sudo ip link set ovs-br0 up
    sudo sysctl -w net.ipv4.ip_forward=1
}

br_test(){
    sudo ovs-vsctl add-br ovs-br0
    sudo ip netns add net1
    sudo ip netns add net2
    sudo ip link add dev veth11 type veth peer name veth12 netns net1
    sudo ip link add dev veth21 type veth peer name veth22 netns net2
    sudo ovs-vsctl add-port ovs-br0 veth11
    sudo ovs-vsctl add-port ovs-br0 veth21
    sudo ip netns exec net1 ip addr add 192.168.64.12/24 dev veth12
    sudo ip netns exec net2 ip addr add 192.168.64.22/24 dev veth22
    sudo ip netns exec net1 ip link set veth12 up
    sudo ip netns exec net2 ip link set veth22 up
    sudo ip link set up veth11
    sudo ip link set up veth21
    sudo ip link set ovs-br0 up
    sudo sysctl -w net.ipv4.ip_forward=1
}

ovs_test 
br_test 

