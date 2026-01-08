
# IP INTERFACE IPTABLES NAT PORT FORWARD NETFILTER

```shell

# link, addr

sudo modprobe dummy

sudo ip link add deth0 type dummy

sudo ip link set dev deth0 address C8:D7:4A:4E:47:50

sudo ip addr add 192.168.1.100/24 brd + dev deth0 # label deth0:0

sudo ip link set dev deth0 up

sudo ip link set dev deth0 down

sudo ip addr del 192.168.1.100/24 brd + dev deth0 # label deth0:0

sudo ip link delete deth0 type dummy

sudo modprobe -r dummy

# route

# to NAT

ip addr add 192.168.10.2/24 dev enp3s0

ip link set dev enp3s0 up

# enp3s0 being the interface the router is connected to
# router WAN IP being 192.168.10.2/24 or something
# router default gateway 192.168.10.1
# router LAN IP being 192.168.100.1/24 or something

# from NAT

ip route add 192.168.10.0/24 via 192.168.100.1 dev eth0

# eth0 being an interface with a connection to the router
# using eth0 gateway router (192.168.100.1) to route to 192.168.10.0/24 network

# route with table 
# ex) add rule as table number 5

ip route add 192.168.10.0/24 dev enp3s0 table 5

# flush to apply 

ip route flush cache

# nexthop different network

sudo ip route add 192.168.122.87 dev enp1s0

sudo ip route add 10.0.2.0/24 via 192.168.122.87 dev enp1s0

# rule 

# all 

ip rule add preference 100 from all lookup 5

# fwmark
# ex) lookup table 5 if marked 5 

ip rule add preference 100 fwmark 5 table 5

# by source 

ip rule add preference 100 from 192.168.0.0/24 lookup 100

```

```shell

# forward

# ephemeral

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# permanent
cat <<EOF | sudo tee /etc/sysctl.d/99-ipv4-forward.conf
net.ipv4.ip_forward                 = 1
EOF

cat <<EOF | sudo tee /etc/sysctl.d/99-ipv6-forward.conf
net.ipv6.conf.all.forwarding                 = 1
EOF

sudo sysctl -p

sudo sysctl --system

```
```shell

# routing steps

# incoming mangle prerouting, fwmark

sudo iptables -t mangle -A PREROUTING -p udp -s 192.168.10.5 -j MARK --set-mark 5

# incoming prerouting

sudo iptables -t nat -A PREROUTING -i wlo1 -p tcp --dport 8888 -j DNAT --to-destination 192.168.1.100:8000

# route decision incoming

# incoming input 

sudo iptables -t nat -A INPUT -i enp3s0 -p udp -s 192.168.10.5 -j SNAT --to-source 192.168.10.50


# route forward if no local 

# forward init rule
sudo iptables -A FORWARD -i wlo1 -o deth0 -p tcp --syn --dport 8888 -m conntrack --ctstate NEW -j ACCEPT

# forward allow all tcp init rule

sudo iptables -A FORWARD -i wlo1 -o deth0 -p tcp -m conntrack --ctstate NEW -j ACCEPT

# forward rules
sudo iptables -A FORWARD -i wlo1 -o deth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -A FORWARD -i deth0 -o wlo1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# forward default DROP

sudo iptables -P FORWARD DROP


# outgoing mangle output 

sudo iptables -t mangle -A OUTPUT -p udp -d 192.168.10.5 -j MARK --set-mark 5

# outgoing output 

sudo iptables -t nat -A OUTPUT -p udp -d 192.168.10.50 -j DNAT --to-destination 192.168.10.5

# route decision out

# outbound including forward

# outgoing postrouting

sudo iptables -t nat -A POSTROUTING -o wlo1 -p tcp -j MASQUERADE

# outgoing postrouting

sudo iptables -t nat -A POSTROUTING -o wlo1 -p tcp -s 192.168.10.50 -j SNAT --to-source 192.168.10.5


# permanent rule

sudo service netfilter-persistent save

# delete 

sudo iptables -S 

iptables -L -n -t nat

sudo iptables -D [ -t nat ] $A_SPEC

# or

sudo iptables -L --line-numbers

sudo iptables -D INPUT $LINE_NUM


# netfilter queue

sudo iptables -I FORWARD -p tcp -j NFQUEUE --queue-num 100

# netfilter queue dev

sudo apt install libnetfilter-queue-dev

```


```shell

# gateway - LAN route scenario
sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up veth2

sudo ip addr add 192.168.62.5/24 dev veth1

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth2


sudo ip netns add net2

sudo ip link add dev veth21 type veth peer name veth22 netns net2

sudo ip link set up veth21

sudo ip netns exec net2 ip link set up veth22

sudo ip addr add 192.168.26.5/24 dev veth21

sudo ip netns exec net2 ip addr add 192.168.26.6/24 dev veth22

sudo sysctl -w net.ipv4.ip_forward=1

sudo iptables -P FORWARD ACCEPT

sudo ip netns exec net1 ip route add 192.168.26.0/24 via 192.168.62.5 dev veth2

sudo ip netns exec net2 ip route add 192.168.62.0/24 via 192.168.26.5 dev veth22

```

```shell
# gateway - WAN route scenario 

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

sudo ip route add 192.168.122.6/32 via 192.168.62.6 dev veth1 table 200

```

```shell

# gateway - forward scenario

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

```



```shell

# gateway - NAT scenario

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

sudo ip netns exec net1 ip addr add 192.168.64.1/24 dev veth3

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.6 dev veth4

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.1 dev veth3

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1

#tcp


sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -i veth2 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -i veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp --syn -o veth2 -m conntrack --ctstate NEW -j ACCEPT

sudo ip netns exec net1 iptables -I FORWARD -p tcp -o veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth3 -j MASQUERADE

sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p tcp -o veth2 -j MASQUERADE


#all


#sudo ip netns exec net1 iptables -I FORWARD -p all -i veth2 -m conntrack --ctstate NEW -j ACCEPT

#sudo ip netns exec net1 iptables -I FORWARD -p all -i veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#sudo ip netns exec net1 iptables -I FORWARD -p all -o veth2 -m conntrack --ctstate NEW -j ACCEPT

#sudo ip netns exec net1 iptables -I FORWARD -p all -o veth2 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p all -o veth3 -j MASQUERADE

#sudo ip netns exec net1 iptables -t nat -I POSTROUTING -p all -o veth2 -j MASQUERADE


sudo ip netns exec net1 iptables -P FORWARD DROP

```

```shell

# gateway - bridge scenario


sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.64.1/24 dev veth1

sudo ip route add 192.168.64.0/24 via 192.168.64.2 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.1 dev veth4

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 ip link add br0 type bridge stp_state 0

sudo ip netns exec net1 ip link set br0 address 12:34:56:78:9a:bc

sudo ip netns exec net1 ip link set veth2 master br0 

sudo ip netns exec net1 ip link set veth3 master br0

sudo ip netns exec net1 ip addr add 192.168.64.2/24 dev br0

sudo ip netns exec net1 ip link set br0 up

sudo ip netns exec net1 ip link set veth2 up 

sudo ip netns exec net1 ip link set veth3 up

sudo ip netns exec net1 ip route add default via 192.168.64.1 dev br0

sudo ip netns exec net1 ip route add 192.168.64.0/24 via 192.168.64.2 dev br0 proto static


```

```shell

# gateway - bridge vlan trunk scenario


sudo ip netns add net1

sudo ip link add dev veth1 type veth peer name veth2 netns net1

sudo ip link set up veth1

sudo ip netns exec net1 ip link set up lo

sudo ip addr add 192.168.64.1/24 dev veth1

sudo ip route add 192.168.64.0/24 dev veth1

sudo ip netns add net2

sudo ip link add dev veth3 type veth peer name veth4 netns net2

sudo ip link set veth3 netns net1

sudo ip netns exec net2 ip link set up veth4

sudo ip netns exec net2 ip addr add 192.168.64.6/24 dev veth4

sudo ip netns exec net2 ip route add default via 192.168.64.1 dev veth4

sudo ip netns exec net1 sysctl -w net.ipv4.ip_forward=1


sudo ip netns exec net1 ip link add br0 type bridge stp_state 0

sudo ip netns exec net1 ip link set br0 address 12:34:56:78:9a:bc

sudo ip netns exec net1 ip link set veth2 master br0 

sudo ip netns exec net1 ip link set veth3 master br0

sudo ip netns exec net1 ip addr add 192.168.64.2/24 dev br0

sudo ip netns exec net1 ip link set br0 up

sudo ip netns exec net1 ip link set veth2 up 

sudo ip netns exec net1 ip link set veth3 up

#sudo ip netns exec net1 ip route add default via 192.168.64.1 dev br0

sudo ip netns exec net1 ip route add default dev br0

sudo ip netns exec net1 ip route add 192.168.64.0/24 dev br0 proto static


# 

sudo ip netns exec net1 ip link set br0 type bridge vlan_filtering 1

sudo ip netns add net3

sudo ip link add dev veth5 type veth peer name veth6 netns net3

sudo ip link set veth5 netns net1

sudo ip netns exec net1 ip link set veth5 master br0

sudo ip netns exec net1 ip link set veth5 up

sudo ip netns exec net3 ip link set up veth6

sudo ip netns exec net3 ip addr add 192.168.66.6/24 dev veth6

sudo ip netns exec net3 ip link set dev veth6 up

sudo ip netns exec net3 ip route add default via 192.168.66.1 dev veth6

sudo ip netns exec net1 bridge vlan add dev veth5 vid 5 pvid untagged master

sudo ip netns exec net1 bridge vlan add dev veth2 vid 5 master

sudo ip netns exec net1 ip route add 192.168.66.0/24 dev br0 proto static


#

sudo ip link add link veth1 name veth1.5 type vlan id 5

sudo ip addr add 192.168.66.1/24 dev veth1.5

sudo ip link set veth1.5 up

```


```shell
# gateway redirect scenario 


# 10.168.0.29 being NAT 

# 10.168.0.26 being default gateway 

# 10.168.0.100 being default gateway's default gateway

# on NAT 

sudo ip netns add vnet 

sudo ip link set enp7s0 netns vnet 

sudo ip netns exec vnet ip addr add 10.168.0.29/24 dev enp7s0

sudo ip netns exec vnet ip link set up dev enp7s0 

sudo ip netns exec vnet ip route add default via 10.168.0.26
 
# on default gateway 

sudo ip rule add preference 221 from 10.168.0.0/24 lookup 221

sudo ip route add default via 10.168.0.100 dev enp7s0 table 221

echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects


```

```shell

# host to different NAT with same ip scenario

# nat1
sudo ip netns add net0

sudo ip link add dev veth01 type veth peer name veth02 netns net0

sudo ip link set up veth01

sudo ip netns exec net0 ip link set up veth02

sudo ip addr add 192.168.10.20/24 dev veth01

sudo ip netns exec net0 ip addr add 192.168.10.2/24 dev veth02

# nat2

sudo ip netns add net1

sudo ip link add dev veth11 type veth peer name veth12 netns net1

sudo ip link set up veth11

sudo ip netns exec net1 ip link set up veth12

sudo ip addr add 192.168.10.30/24 dev veth11

sudo ip netns exec net1 ip addr add 192.168.10.2/24 dev veth12

sudo ip rule add preference 100 from all lookup local

sudo ip rule del preference 0

sudo ip rule add preference 92 fwmark 2 table 92
sudo ip rule add preference 93 fwmark 3 table 93

sudo ip route add default via 192.168.10.20 dev veth01 table 92
sudo ip route add default via 192.168.10.30 dev veth11 table 93


sudo iptables -t nat -A INPUT -p tcp -i veth02 -j SNAT --to-source 192.168.10.3
sudo iptables -t mangle -A OUTPUT -p tcp -d 192.168.10.2 -j MARK --set-mark 2
sudo iptables -t mangle -A OUTPUT -p tcp -d 192.168.10.3 -j MARK --set-mark 3
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.10.3 -j DNAT --to-destination 192.168.10.2

sudo ip route flush cache


# test

# in net0
sudo ip netns exec net0 nc -l 192.168.10.2 9999

# in net1 
sudo ip netns exec net1 nc -l 192.168.10.2 9999

# on host
nc 192.168.10.2 9999 

# on host
nc 192.168.10.3 9999


```

```shell

# network namespace

sudo ip netns add net1

sudo ip netns del net1

sudo ip -all netns exec ip link show

# veth namespace

ip link add veth1 netns net1 type veth

ip link add veth1 netns net1 type veth peer name veth2 netns net2

# veth

sudo ip link add veth1 type veth


sudo ip addr add 192.168.1.1/24 brd + dev veth0

sudo ip addr add 192.168.1.5/24 brd + dev veth1

sudo ip link set dev veth0 up

sudo ip link set dev veth1 up

sudo ip link set dev veth1 down

sudo ip link set dev veth0 down

sudo ip addr del 192.168.1.1/24 brd + dev veth0

sudo ip addr del 192.168.1.5/24 brd + dev veth1

sudo ip link del veth1 type veth

# veth with peer

sudo ip link add br-blah01 type bridge 

sudo ip link add dev vm1 type veth peer name vm2

sudo ip link set vm1 master br-blah01

sudo ip addr add 10.0.0.1/24 dev br-blah01

sudo ip addr add 10.0.0.2/24 dev vm2

sudo ip link set br-blah01 up

sudo ip link set vm1 up

sudo ip link set vm2 up


```
```shell

# bridge

sudo ip link add br0 type bridge 

ip link set br0 type bridge stp_state 1

# ip link set br0 type bridge vlan_filtering 1

ip link set eth1 master br0

ip link set eth1 up

ip link set br0 up


```

```shell

# tuntap

sudo ip tuntap add mode tap tap0

sudo ip addr add 192.168.1.100/24 brd + dev tap0

sudo ip link set tap0 master br0

sudo ip link set dev tap0 up

```


```shell

# vlan

sudo apt-get install vlan

sudo modprobe 8021q

# permanent

echo "8021q" >> /etc/modules

sudo ip link add link eth0 name eth0.100 type vlan id 5

sudo ip link set eth0.100 up





# del

sudo ip link set eth0.100 down

sudo ip link del eth0.100


```


```shell

# vxlan

# on host1

sudo ip netns add top

sudo ip link add top-in type veth peer name top-out

sudo ip link set top-in netns top

sudo ip netns exec top ip addr add 10.10.5.2/16 dev top-in

sudo ip netns exec top ip link set top-in up

# on host1: bridge

sudo ip link add middle type bridge

sudo ip addr add 10.10.5.1/16 dev middle

sudo ip link set top-out master middle

sudo ip link set top-out up

sudo ip link set middle up

# on host1: route

sudo ip netns exec top ip route add default via 10.10.5.1

# on host1: vxlan

sudo ip link add vxlan-top type vxlan id 100 local 192.168.99.1 remote 192.168.99.2 dev eth0

sudo ip link set vxlan-top master middle

sudo ip link set vxlan-top up


# on host2

sudo ip netns add bottom

sudo ip link add bottom-in type veth peer name bottom-out

sudo ip link set bottom-in netns bottom

sudo ip netns exec bottom ip addr add 10.10.5.12/16 dev bottom-in

sudo ip netns exec bottom ip link set bottom-in up

# on host2: bridge

sudo ip link add middle type bridge

sudo ip addr add 10.10.5.11/16 dev middle

sudo ip link set bottom-out master middle

sudo ip link set bottom-out up

sudo ip link set middle up

# on host2: route

sudo ip netns exec bottom ip route add default via 10.10.5.11


# on host1: vxlan

sudo ip link add vxlan-bottom type vxlan id 100 local 192.168.99.2 remote 192.168.99.1 dev eth0

sudo ip link set vxlan-bottom master middle

sudo ip link set vxlan-bottom up

# test

# on host1
sudo ip netns exec top ncat -l 10.10.5.2 9999

# on host2


sudo ip netns exec bottom ncat 10.10.5.2 9999

```


```shell
# macvlan

ip link add macvlan1 link eth0 type macvlan mode bridge

ip netns add net1

ip link set macvlan1 netns net1

ip netns exec net1 ip link set macvlan1 up 

ip netns exec net1 ip link addr add 192.168.0.16 dev macvlan1


```

```shell

# bond 

#ip link add bond1 type bond miimon 100 mode active-backup
ip link add bond1 type bond miimon 100 mode balance-xor
ip link addr add $ETH0_ADDR dev bond1 
ip link set eth0 master bond1
ip link set eth1 master bond1
ip link set bond1 up
```

```shell

# netkit

sudo ip netns add net1

sudo ip link add nkpeer0 type netkit

sudo ip link set nkpeer0 netns net1

sudo ip link set dev nk0 up

sudo ip netns exec net1 ip link set dev nkpeer0 up

sudo ip addr add 10.168.0.1/24 dev nk0

sudo ip netns exec net1 ip addr add 10.168.0.2/24 dev nkpeer0


```

```shell


# xfrm

# xfrm ip addr


sudo ip netns add vnet
sudo ip link add dev veth01 type veth peer name veth02 netns vnet
sudo ip addr add 192.168.10.1/24 dev veth01
sudo ip addr add 10.168.66.1/24 dev veth01
sudo ip link set up veth01
sudo ip netns exec vnet ip addr add 192.168.10.2/24 dev veth02
sudo ip netns exec vnet ip addr add 10.168.66.2/24 dev veth02
sudo ip netns exec vnet ip link set up veth02

# xfrm state, policy

# client

ip xfrm state add \
    src 10.168.66.1/24 dst 10.168.66.2/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.1/24 dst 10.168.66.2/24 


ip xfrm state add \
    src 10.168.66.2/24 dst 10.168.66.1/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.2/24 dst 10.168.66.1/24 

ip xfrm policy add \
    src 10.168.66.1/24 dst 10.168.66.2/24 dir out \
    tmpl src 10.168.66.1/24 dst 10.168.66.2/24 proto esp reqid 0x01000000 mode tunnel

ip xfrm policy add \
    src 10.168.66.2/24 dst 10.168.66.1/24 dir in \
    tmpl src 10.168.66.2/24 dst 10.168.66.1/24 proto esp reqid 0x02000000 mode tunnel


# server

ip netns exec vnet ip xfrm state add \
    src 10.168.66.1/24 dst 10.168.66.2/24 proto esp spi 0x01000000 reqid 0x01000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.1/24 dst 10.168.66.2/24


ip netns exec vnet ip xfrm state add \
    src 10.168.66.2/24 dst 10.168.66.1/24 proto esp spi 0x02000000 reqid 0x02000000 mode tunnel flag af-unspec \
    aead 'rfc4106(gcm(aes))' 0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeff 128 \
    sel src 10.168.66.2/24 dst 10.168.66.1/24 

ip netns exec vnet ip xfrm policy add \
    src 10.168.66.1/24 dst 10.168.66.2/24 dir in \
    tmpl src 10.168.66.1/24 dst 10.168.66.2/24 proto esp reqid 0x01000000 mode tunnel

ip netns exec vnet ip xfrm policy add \
    src 10.168.66.2/24 dst 10.168.66.1/24 dir out \
    tmpl src 10.168.66.2/24 dst 10.168.66.1/24 proto esp reqid 0x02000000 mode tunnel



```


```shell
# gre


sudo sysctl -w net.ipv4.ip_forward=1

sudo ip tunnel add gre1 mode gre remote <HOST_B_IP> local <HOST_A_IP> ttl 25

sudo ip addr add <HOST_A_PRIV_IP> dev gre1

sudo ip link set gre1 up

```

# NFTABLES NFT


```shell

# iptables translate, outputs nftables equivalent

iptables-translate -A INPUT -i enp1s0 -p tcp --dport 22 -j ACCEPT

# list

sudo nft list ruleset

# default file at
# /etc/nftools.conf
# or /etc/nftables.conf

# can use include syntax 

include "ipv4-ipv5-webserver-rules.nft"


```

# CONNTRACK


```shell

sudo apt-get install conntrack


sudo conntrack -L

# delete
conntrack -D -p tcp --dport 993

```