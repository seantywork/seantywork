# net-optimize



```shell
# most effective to lesser

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
/proc/sys/net/core/rps_sock_flow_entries # 32768 or more
/sys/class/net/enp1s0/queues/rx-1/rps_flow_cnt # (/proc/sys/net/core/rps_sock_flow_entries) / N(rx queue len)

# netdev
sysctl net.core.netdev_max_backlog

# mem
sysctl net.core.wmem_default
sysctl net.core.wmem_max
sysctl net.core.rmem_default
sysctl net.core.rmem_max

# conntrack

net.netfilter.nf_conntrack_max # larger
net.netfilter.nf_conntrack_tcp_timeout_established # shorter

# rxtx ring

$ sudo ethtool -g enp1s0 
Ring parameters for enp1s0:
Pre-set maximums:
RX:                     256
RX Mini:                n/a
RX Jumbo:               n/a
TX:                     256
TX push buff len:       n/a
Current hardware settings:
RX:                     256
RX Mini:                n/a
RX Jumbo:               n/a
TX:                     256
RX Buf Len:             n/a
CQE Size:               n/a
TX Push:                off
RX Push:                off
TX push buff len:       n/a
TCP data split:         n/a

# arp gc
net.ipv4.neigh.default.gc_stale_time
net.ipv4.neigh.default.gc_thresh1
net.ipv4.neigh.default.gc_thresh2
net.ipv4.neigh.default.gc_thresh3

```