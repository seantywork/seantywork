#!/bin/bash

# create d_if

sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2

sudo ip netns exec net1 ip route add default via 192.168.62.5 dev veth2


sudo sysctl -w net.ipv4.ip_forward=1

#tcp

sudo iptables -t nat -I PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 192.168.62.6:8000


sudo iptables -I FORWARD -p tcp --syn -i ens3 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p tcp -i ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p tcp --syn -o ens3 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p tcp -o ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


sudo iptables -P FORWARD DROP

#sudo iptables -t nat -I POSTROUTING -p tcp -o ens3 -j SNAT --to-source 192.168.122.87

# or

sudo iptables -t nat -I POSTROUTING -p tcp -o ens3 -j MASQUERADE



#udp

sudo iptables -t nat -I PREROUTING -p udp --dport 8888 -j DNAT --to-destination 192.168.62.6:8000

sudo iptables -I FORWARD -p udp -i ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p udp -i ens3 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p udp -o ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p udp -o ens3 -m conntrack --ctstate NEW -j ACCEPT


#sudo iptables -t nat -I POSTROUTING -p udp -o ens3 -j SNAT --to-source 192.168.122.87

# or

sudo iptables -t nat -I POSTROUTING -p udp -o ens3 -j MASQUERADE

#icmp 


sudo iptables -I FORWARD -p icmp -i ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p icmp -i ens3 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -I FORWARD -p icmp -o ens3 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD -p icmp -o ens3 -m conntrack --ctstate NEW -j ACCEPT


#sudo iptables -t nat -I POSTROUTING -p udp -o ens3 -j SNAT --to-source 192.168.122.87

# or

sudo iptables -t nat -I POSTROUTING -p icmp -o ens3 -j MASQUERADE