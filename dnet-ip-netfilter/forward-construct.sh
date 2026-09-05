#!/bin/bash

sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth2

# sudo ip route add 192.168.64.0/24 via 192.168.62.6 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net1 ip link set up veth3

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net1 ip addr add 192.168.64.1/24 dev veth3

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.6 dev veth4

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.1 dev veth3

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


#tcp

sudo ip netns exec net1 iptables -t nat -I PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 192.168.64.6:8000


sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -i veth3 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -i veth3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -o veth3 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -o veth3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


sudo ip netns exec net1 iptables -P FORWARD DROP

#sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth3 -j SNAT --to-source 192.168.64.1

# or

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth2 -j MASQUERADE

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth3 -j MASQUERADE
