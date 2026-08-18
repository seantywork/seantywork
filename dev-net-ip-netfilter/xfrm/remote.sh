#!/bin/bash 

set -xe

make clean
make

sudo ip netns add vnet
sudo ip link add dev kxfrm0 type veth peer name kxfrm1 netns vnet
sudo ip addr add 10.168.66.1/24 dev kxfrm0
sudo ip addr add 192.168.10.1/24 dev kxfrm0
sudo ip link set dev kxfrm0 up
sudo ip netns exec vnet ip addr add 10.168.66.2/24 dev kxfrm1
sudo ip netns exec vnet ip addr add 172.31.99.2/32 dev kxfrm1
sudo ip netns exec vnet ip link set dev kxfrm1 up
sudo ip netns exec vnet ip link set dev lo up

sudo ip rule add preference 100 from all lookup 100
sudo ip route add 172.31.99.2/32 dev kxfrm0 proto static src 192.168.10.1 table 100
sudo sysctl -w net.ipv4.ip_forward=1
./espinudp_enable.out 10.168.66.1 &

sudo ip netns exec vnet ip rule add preference 100 from all lookup 100
sudo ip netns exec vnet ip route add 192.168.10.0/24 dev kxfrm1 proto static src 172.31.99.2 table 100
sudo ip netns exec vnet sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec vnet ./espinudp_enable.out 10.168.66.2 &
