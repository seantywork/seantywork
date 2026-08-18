#!/bin/bash


setup(){
    sudo ip netns add net1
    sudo ip netns add net2
    sudo ip link add dev veth11 type veth peer name veth12 netns net1
    sudo ip link add dev veth21 type veth peer name veth22 netns net2
    sudo ip netns exec net1 ip addr add 192.168.64.12/24 dev veth12
    sudo ip netns exec net2 ip addr add 192.168.64.22/24 dev veth22
    sudo ip netns exec net1 ip link set veth12 up
    sudo ip netns exec net2 ip link set veth22 up
    sudo sysctl -w net.ipv4.ip_forward=1
}

br_test(){
    sudo ip link add lx-br0 type bridge stp_state 0
    sudo ip link set veth11 master lx-br0
    sudo ip link set veth21 master lx-br0
    sudo ip link set up veth11
    sudo ip link set up veth21
    sudo ip link set up lx-br0
    sudo ip netns exec net2 iperf3 -s 192.168.64.22 > /dev/null 2>&1 &
    sudo ip netns exec net1 iperf3 -c 192.168.64.22 -t 60 -i 1 -P 4
    sudo ip netns exec net2 pkill iperf3
    sudo ip link del lx-br0
}


ovs_test(){
    sudo ovs-vsctl add-br ovs-br0
    sudo ovs-vsctl add-port ovs-br0 veth11
    sudo ovs-vsctl add-port ovs-br0 veth21
    sudo ip link set up veth11
    sudo ip link set up veth21
    sudo ip link set ovs-br0 up
    sudo ip netns exec net2 iperf3 -s 192.168.64.22 > /dev/null 2>&1 &
    sudo ip netns exec net1 iperf3 -c 192.168.64.22 -t 60 -i 1 -P 4
    sudo ip netns exec net2 pkill iperf3
    sudo ovs-vsctl del-br ovs-br0
    
}

cleanup(){
    sudo ip netns del net1
    sudo ip netns del net2
}

setup
br_test
cleanup
setup
ovs_test
cleanup