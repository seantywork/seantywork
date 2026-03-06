# 01

```shell
./setup.sh

```

# 02
```shell

----------------------
|     host network   |
|                    |
|       veth11       |
|     (192.168.62.5) |
-----------|----------
           |
           |
-----------|----------
|     (192.168.62.6) |
|       veth12       |
|                    |
|     net1 network   |
----------------------
```

# 03

```shell

cd tls

./certgen.sh

make

```

# 04
```shell
# /etc/hosts

192.168.62.6 quicbench
```

# 05
```shell
thy@thy-Z370-HD3:~/hack/linux/linuxyz/quic-bench/tls$ sudo ip netns exec net1 ./tls.out s

```

```shell
thy@thy-Z370-HD3:~/hack/linux/linuxyz/quic-bench/tls$ ./tls.out c

```

# 06

```shell
# tls server
client connected
receiving...
sec: 14 ms: 265
server recvd total: 4294967296
```

```shell
# tls client
verify_callback (depth=1)(preverify=1)
  Issuer (cn): quicroot
  Subject (cn): quicroot
verify_callback (depth=0)(preverify=1)
  Issuer (cn): quicroot
  Subject (cn): quichbench
  Subject (san): quicbench
connected, sending...
client sent total: 4294967296
```

# 07
```shell
cd quic

./setup.sh

./certgen.sh

make

```

# 08
```shell

thy@thy-Z370-HD3:~/hack/linux/linuxyz/quic-bench/quic$ sudo ip netns exec net1 ./quic.out s
```
```shell

thy@thy-Z370-HD3:~/hack/linux/linuxyz/quic-bench/quic$ ./quic.out c
```

# 09

```shell
# quic server
client connected
client stream started
sec: 0 ms: 58
server recvd total: 8388608
client shut down
successfully shut down on idle
stream done
connection done
all data is valid
```

```shell
client: quic event connected
connected
resumption ticket received: 2486 bytes
client sending...
client send done
client sent total: 8388608
successfully shut down on idle
stream done
connection done

```

# 10

```c
// quic.h

//#define DATA_VALIDITY_CHECK 1
#define DATA_VALIDITY_CHECK 0
#define ACK_CHECK 1

```

# 11
```shell
make clean
make

```

# 12

```shell
# quic server
client connected
client stream started
sec: 9 ms: 375
server recvd total: 4294967296
client shut down
successfully shut down on idle
stream done
connection done

```

```shell
# quic client
client: quic event connected
connected
resumption ticket received: 2486 bytes
client sending...
client send done
client sent total: 4294967296
successfully shut down on idle
stream done
connection done
```

# 13

```c
// quic.h

#define DATA_VALIDITY_CHECK 1
//#define DATA_VALIDITY_CHECK 0
//#define ACK_CHECK 1
#define ACK_CHECK 0

```

# 14
```shell
make clean
make

```

# 15
```shell
# quic server
client connected
client stream started
successfully shut down on idle
stream done
connection done
invalid data at: 158720: �(a)
invalid data at: 158721: (a)
invalid data at: 158722: �(a)
invalid data at: 158723: �(a)
invalid data at: 158724: (a)
invalid data at: 158725: (a
....
```

```shell
# quic client

client: quic event connected
connected
resumption ticket received: 2486 bytes
client sending...
client send done
client sent total: 8388608
Segmentation fault
```