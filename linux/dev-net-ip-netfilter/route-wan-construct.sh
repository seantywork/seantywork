#!/bin/bash



sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth2

sudo ip route add 192.168.64.0/24 via 192.168.62.6 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net1 ip link set up veth3

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net1 ip addr add 192.168.122.1/24 dev veth3

sudo ip netns exec net2 ip addr add 192.168.122.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.122.1 dev veth4

sudo ip netns exec net1 ip route add 192.168.122.0/24 via 192.168.122.1 dev veth3

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 iptables -P FORWARD ACCEPT


sudo iptables -I FORWARD -p all -i veth1 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p all -i veth1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p all -o veth1 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p all -o veth1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -t nat -I POSTROUTING -p all -o veth1 -j MASQUERADE

sudo iptables -t nat -I POSTROUTING -p all -o ens3 -j MASQUERADE


sudo iptables -P FORWARD DROP

sudo ip rule add preference 200 from all lookup 200 

sudo ip route add 192.168.122.6/32 via 192.168.62.6