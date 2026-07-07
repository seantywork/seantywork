# net-optimize

```shell
# rss
$ sudo ethtool -l enp1s0 
[sudo] password for thy: 
Channel parameters for enp1s0:
Pre-set maximums:
RX:             n/a
TX:             n/a
Other:          n/a
Combined:       4
Current hardware settings:
RX:             n/a
TX:             n/a
Other:          n/a
Combined:       4

# rps
$ sudo cat /sys/class/net/enp1s0/queues/rx-1/rps_cpus 
f

# rfs
```