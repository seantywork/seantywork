# install ovs

```shell
./ovs-install.sh
```

# start ovs 

```shell
+ mkdir -p /usr/local/etc/openvswitch
+ pushd ovs
~/hack/linuxyz/br-ovs/ovs ~/hack/linuxyz/br-ovs
+ sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema
+ popd
~/hack/linuxyz/br-ovs
+ sudo /usr/local/share/openvswitch/scripts/ovs-ctl start
 * Starting ovsdb-server
 * system ID not configured, please use --system-id
 * Configuring Open vSwitch system IDs
 * Inserting openvswitch module
 * Starting ovs-vswitchd
 * Enabling remote OVSDB managers
+ sudo ovs-vsctl --no-wait init

```

# br

```shell
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec  97.0 GBytes  13.9 Gbits/sec   48             sender
[  5]   0.00-60.00  sec  97.0 GBytes  13.9 Gbits/sec                  receiver
[  7]   0.00-60.00  sec  99.2 GBytes  14.2 Gbits/sec    5             sender
[  7]   0.00-60.00  sec  99.2 GBytes  14.2 Gbits/sec                  receiver
[  9]   0.00-60.00  sec  96.9 GBytes  13.9 Gbits/sec    4             sender
[  9]   0.00-60.00  sec  96.9 GBytes  13.9 Gbits/sec                  receiver
[ 11]   0.00-60.00  sec  97.7 GBytes  14.0 Gbits/sec   88             sender
[ 11]   0.00-60.00  sec  97.7 GBytes  14.0 Gbits/sec                  receiver
[SUM]   0.00-60.00  sec   391 GBytes  56.0 Gbits/sec  145             sender
[SUM]   0.00-60.00  sec   391 GBytes  56.0 Gbits/sec                  receiver
```

```shell
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   110 GBytes  15.8 Gbits/sec    5             sender
[  5]   0.00-60.00  sec   110 GBytes  15.8 Gbits/sec                  receiver
[  7]   0.00-60.00  sec   110 GBytes  15.7 Gbits/sec    9             sender
[  7]   0.00-60.00  sec   110 GBytes  15.7 Gbits/sec                  receiver
[  9]   0.00-60.00  sec   113 GBytes  16.1 Gbits/sec    7             sender
[  9]   0.00-60.00  sec   113 GBytes  16.1 Gbits/sec                  receiver
[ 11]   0.00-60.00  sec   113 GBytes  16.1 Gbits/sec    5             sender
[ 11]   0.00-60.00  sec   113 GBytes  16.1 Gbits/sec                  receiver
[SUM]   0.00-60.00  sec   446 GBytes  63.8 Gbits/sec   26             sender
[SUM]   0.00-60.00  sec   446 GBytes  63.8 Gbits/sec                  receiver
```

# ovs

```shell
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   107 GBytes  15.3 Gbits/sec  243             sender
[  5]   0.00-60.00  sec   107 GBytes  15.3 Gbits/sec                  receiver
[  7]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec  476             sender
[  7]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec                  receiver
[  9]   0.00-60.00  sec   105 GBytes  15.0 Gbits/sec   55             sender
[  9]   0.00-60.00  sec   105 GBytes  15.0 Gbits/sec                  receiver
[ 11]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec    5             sender
[ 11]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec                  receiver
[SUM]   0.00-60.00  sec   427 GBytes  61.2 Gbits/sec  779             sender
[SUM]   0.00-60.00  sec   427 GBytes  61.1 Gbits/sec                  receiver
```

```shell
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec    4             sender
[  5]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec                  receiver
[  7]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec    6             sender
[  7]   0.00-60.00  sec   108 GBytes  15.4 Gbits/sec                  receiver
[  9]   0.00-60.00  sec   107 GBytes  15.4 Gbits/sec    1             sender
[  9]   0.00-60.00  sec   107 GBytes  15.4 Gbits/sec                  receiver
[ 11]   0.00-60.00  sec   107 GBytes  15.3 Gbits/sec    6             sender
[ 11]   0.00-60.00  sec   107 GBytes  15.3 Gbits/sec                  receiver
[SUM]   0.00-60.00  sec   429 GBytes  61.5 Gbits/sec   17             sender
[SUM]   0.00-60.00  sec   429 GBytes  61.5 Gbits/sec                  receiver
```