
# 00

```shell
            ----------------------------------------
            |            bridge                    |
            |               (NAT)                  |
            |            192.168.122.1/24          |
            --------------|---------------|---------
                          |               |
--------------------------|-----     -----|-------------------------
|       router0                 |    |      router1                |
|    (ubuntu24-server VM)       |    |    (ubuntu-24-2 VM)         |
|       192.168.122.204/24      |    |       192.168.122.200/24    |
|                      |        |    |                             |
|    ------------------|------- |    |  -------------------------- |
|    |     network0           | |    |  |     network1           | |
|    |      (net1 namespace)  | |    |  |      (net1 namespace)  | |
|    |      10.0.10.2/24      | |    |  |      10.0.11.2/24      | |
--------------------------------      ------------------------------

```


# 01

```shell
thy@ubuntu24-server:~/box$ sudo ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:e2:07:25 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.204/24 metric 100 brd 192.168.122.255 scope global dynamic enp1s0
       valid_lft 2074sec preferred_lft 2074sec
    inet6 fe80::5054:ff:fee2:725/64 scope link 
       valid_lft forever preferred_lft forever


```

# 02

```shell

thy@ubuntu-24-2:~/box$ sudo ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:e2:07:21 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.200/24 metric 100 brd 192.168.122.255 scope global dynamic enp1s0
       valid_lft 2102sec preferred_lft 2102sec
    inet6 fe80::5054:ff:fee2:721/64 scope link 
       valid_lft forever preferred_lft forever

```
# 03

```shell

thy@ubuntu-24-2:~/box$ nc -l 192.168.122.200 9999

```

```shell
thy@ubuntu24-server:~/box$ nc 192.168.122.200 9999
qwer


```

# 04

```shell

sudo apt update
sudo apt install bird tshark

sudo systemctl stop bird
```

# 05

```shell

./on0.sh

```

```shell

./on1.sh

```

# 06

```shell

thy@ubuntu24-server:~/box$ ip a
...
4: veth1@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 86:59:90:1a:4a:60 brd ff:ff:ff:ff:ff:ff link-netns net1
    inet 10.0.10.1/24 scope global veth1
       valid_lft forever preferred_lft forever
    inet6 fe80::8459:90ff:fe1a:4a60/64 scope link 
       valid_lft forever preferred_lft forever

```

# 07

```shell

thy@ubuntu24-server:~/box$ sudo ip netns exec net1 ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: veth2@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 9a:45:f6:36:e8:cb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.10.2/24 scope global veth2
       valid_lft forever preferred_lft forever
    inet6 fe80::9845:f6ff:fe36:e8cb/64 scope link 
       valid_lft forever preferred_lft forever



```


# 08

```shell
thy@ubuntu-24-2:~$ sudo tshark -i veth1
Running as user "root" and group "root". This could be dangerous.
Capturing on 'veth1'


```

# 09

```shell
thy@ubuntu-24-2:~/box$ sudo ip netns exec net1 nc -l 10.0.11.2 9999


```
```shell

thy@ubuntu24-server:~/box$ sudo ip netns exec net1 nc 10.0.11.2 9999


```

# 10

```shell
thy@ubuntu24-server:~/box$ sudo ip route add 192.168.122.200 dev enp1s0
thy@ubuntu24-server:~/box$ sudo ip route add 10.0.11.0/24 via 192.168.122.200 dev enp1s0
```

```shell
thy@ubuntu-24-2:~/box$ sudo ip route add 192.168.122.204 dev enp1s0
thy@ubuntu-24-2:~/box$ sudo ip route add 10.0.10.0/24 via 192.168.122.204 dev enp1s0
```

# 11

```shell
thy@ubuntu-24-2:~/box$ sudo ip netns exec net1 nc -l 10.0.11.2 9999

```

```shell
thy@ubuntu24-server:~/box$ sudo ip netns exec net1 nc 10.0.11.2 9999
asdf
```
# 12

```shell

    7 209.216657001    10.0.10.2 → 10.0.11.2    TCP 74 54346 → 9999 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2153550491 TSecr=0 WS=128
    8 209.216718956    10.0.11.2 → 10.0.10.2    TCP 74 9999 → 54346 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM TSval=1584711764 TSecr=2153550491 WS=128
    9 209.217147388    10.0.10.2 → 10.0.11.2    TCP 66 54346 → 9999 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=2153550492 TSecr=1584711764
   10 211.003022696    10.0.10.2 → 10.0.11.2    TCP 71 54346 → 9999 [PSH, ACK] Seq=1 Ack=1 Win=64256 Len=5 TSval=2153552277 TSecr=1584711764
   11 211.003087706    10.0.11.2 → 10.0.10.2    TCP 66 9999 → 54346 [ACK] Seq=1 Ack=6 Win=65280 Len=0 TSval=1584713551 TSecr=2153552277

```

# 13

```shell
thy@ubuntu24-server:~/box$ sudo ip route del 192.168.122.200 dev enp1s0
thy@ubuntu24-server:~/box$ sudo ip route del 10.0.11.0/24 via 192.168.122.200 dev enp1s0

```
```shell
thy@ubuntu-24-2:~/box$ sudo ip route del 192.168.122.204 dev enp1s0
thy@ubuntu-24-2:~/box$ sudo ip route del 10.0.10.0/24 via 192.168.122.204 dev enp1s0

```

# 14

```shell
vim /etc/bird/bird.conf

```


# 15

```shell
sudo systemctl restart bird
```

# 16

```shell
thy@ubuntu24-server:~/box$ sudo birdc show protocols
BIRD 1.6.8 ready.
name     proto    table    state  since       info
kernel1  Kernel   master   up     23:45:55    
device1  Device   master   up     23:45:55    
direct1  Direct   master   up     23:45:55    
b0       BGP      master   up     23:45:59    Established  

thy@ubuntu24-server:~/box$ sudo birdc show route
BIRD 1.6.8 ready.
10.0.10.0/24       dev veth1 [direct1 23:45:55] * (240)
10.0.11.0/24       via 192.168.122.200 on enp1s0 [b0 23:45:59] * (100) [AS64521i]
192.168.122.0/24   dev enp1s0 [direct1 23:45:55] * (240)
                   via 192.168.122.200 on enp1s0 [b0 23:45:59] (100) [AS64521i]


```
```shell
thy@ubuntu-24-2:~/box$ sudo birdc show protocols
BIRD 1.6.8 ready.
name     proto    table    state  since       info
kernel1  Kernel   master   up     23:45:59    
device1  Device   master   up     23:45:59    
direct1  Direct   master   up     23:45:59    
b1       BGP      master   up     23:45:59    Established 

thy@ubuntu-24-2:~/box$ sudo birdc show route
BIRD 1.6.8 ready.
10.0.10.0/24       via 192.168.122.204 on enp1s0 [b1 23:45:59] * (100) [AS64520i]
10.0.11.0/24       dev veth1 [direct1 23:45:59] * (240)
192.168.122.0/24   dev enp1s0 [direct1 23:45:59] * (240)
                   via 192.168.122.204 on enp1s0 [b1 23:45:59] (100) [AS64520i]


```

# 17

```shell
thy@ubuntu24-server:~/box$ sudo ip route
default via 192.168.122.1 dev enp1s0 proto dhcp src 192.168.122.204 metric 100 
10.0.10.0/24 dev veth1 proto kernel scope link src 10.0.10.1 
10.0.11.0/24 via 192.168.122.200 dev enp1s0 proto bird 
192.168.122.0/24 dev enp1s0 proto kernel scope link src 192.168.122.204 metric 100 
192.168.122.1 dev enp1s0 proto dhcp scope link src 192.168.122.204 metric 100 
```
```shell
thy@ubuntu-24-2:~/box$ sudo ip route
default via 192.168.122.1 dev enp1s0 proto dhcp src 192.168.122.200 metric 100 
10.0.10.0/24 via 192.168.122.204 dev enp1s0 proto bird 
10.0.11.0/24 dev veth1 proto kernel scope link src 10.0.11.1 
192.168.122.0/24 dev enp1s0 proto kernel scope link src 192.168.122.200 metric 100 
192.168.122.1 dev enp1s0 proto dhcp scope link src 192.168.122.200 metric 100

```

# 18

```shell
thy@ubuntu24-server:~$ sudo tshark -i veth1
Running as user "root" and group "root". This could be dangerous.
Capturing on 'veth1'

```
```shell
thy@ubuntu-24-2:~$ sudo tshark -i veth1
Running as user "root" and group "root". This could be dangerous.
Capturing on 'veth1'

```

# 19

```shell

thy@ubuntu-24-2:~/box$ sudo ip netns exec net1 nc -l 10.0.11.2 9999
```

```shell

thy@ubuntu24-server:~/box$ sudo ip netns exec net1 nc 10.0.11.2 9999
bgp helloo!!!!

```

# 20

```shell
thy@ubuntu24-server:~$ sudo tshark -i veth1
Running as user "root" and group "root". This could be dangerous.
Capturing on 'veth1'
    1 0.000000000    10.0.10.2 → 10.0.11.2    TCP 74 53488 → 9999 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2154111861 TSecr=0 WS=128
    2 0.000337346    10.0.11.2 → 10.0.10.2    TCP 74 9999 → 53488 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM TSval=1585273134 TSecr=2154111861 WS=128
    3 0.000354149    10.0.10.2 → 10.0.11.2    TCP 66 53488 → 9999 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=2154111861 TSecr=1585273134
    4 5.292822389 86:59:90:1a:4a:60 → 9a:45:f6:36:e8:cb ARP 42 Who has 10.0.10.2? Tell 10.0.10.1
    5 5.292843243 9a:45:f6:36:e8:cb → 86:59:90:1a:4a:60 ARP 42 Who has 10.0.10.1? Tell 10.0.10.2
    6 5.293009682 86:59:90:1a:4a:60 → 9a:45:f6:36:e8:cb ARP 42 10.0.10.1 is at 86:59:90:1a:4a:60
    7 5.292981525 9a:45:f6:36:e8:cb → 86:59:90:1a:4a:60 ARP 42 10.0.10.2 is at 9a:45:f6:36:e8:cb
    8 8.448817263    10.0.10.2 → 10.0.11.2    TCP 81 53488 → 9999 [PSH, ACK] Seq=1 Ack=1 Win=64256 Len=15 TSval=2154120310 TSecr=1585273134
    9 8.449367387    10.0.11.2 → 10.0.10.2    TCP 66 9999 → 53488 [ACK] Seq=1 Ack=16 Win=65152 Len=0 TSval=1585281583 TSecr=2154120310


```

```shell
thy@ubuntu-24-2:~$ sudo tshark -i veth1
Running as user "root" and group "root". This could be dangerous.
Capturing on 'veth1'
    1 0.000000000    10.0.10.2 → 10.0.11.2    TCP 74 53488 → 9999 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2154111861 TSecr=0 WS=128
    2 0.000056658    10.0.11.2 → 10.0.10.2    TCP 74 9999 → 53488 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM TSval=1585273134 TSecr=2154111861 WS=128
    3 0.000197636    10.0.10.2 → 10.0.11.2    TCP 66 53488 → 9999 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=2154111861 TSecr=1585273134
    4 5.093841101 06:63:34:0b:98:ef → 7e:9f:2d:eb:7c:33 ARP 42 Who has 10.0.11.2? Tell 10.0.11.1
    5 5.093832531 7e:9f:2d:eb:7c:33 → 06:63:34:0b:98:ef ARP 42 Who has 10.0.11.1? Tell 10.0.11.2
    6 5.093891327 06:63:34:0b:98:ef → 7e:9f:2d:eb:7c:33 ARP 42 10.0.11.1 is at 06:63:34:0b:98:ef
    7 5.093898882 7e:9f:2d:eb:7c:33 → 06:63:34:0b:98:ef ARP 42 10.0.11.2 is at 7e:9f:2d:eb:7c:33
    8 8.448882261    10.0.10.2 → 10.0.11.2    TCP 81 53488 → 9999 [PSH, ACK] Seq=1 Ack=1 Win=64256 Len=15 TSval=2154120310 TSecr=1585273134
    9 8.448965966    10.0.11.2 → 10.0.10.2    TCP 66 9999 → 53488 [ACK] Seq=1 Ack=16 Win=65152 Len=0 TSval=1585281583 TSecr=2154120310

```

