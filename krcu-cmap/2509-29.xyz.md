# krcu-cmap

- source: [linuxyz/krcu-cmap](https://github.com/seantywork/seantywork/tree/main/krcu-cmap)
- date: 2509-24

# 01

```shell
# a regular old concurrent map...
concurrent_map
|     bucket_count
|     bucket_0-------
|     |     spin_lock      
|     |     node_0----node_1----node_n
|     bucket_1-------
|     |     spin_lock
|     |     node_0----node_1----node_n
|     bucket_2-------
|     |     spin_lock
|     |     node_0----node_1----node_n
|     bucket_n-------
|     |     spin_lock
|     |     node_0----node_1----node_n
|     ----------------
|     |
---------------
```
# 02

```c
struct node {
    int key;
    int value;
	struct list_head _node; 
	struct rcu_head _rcu; // <----- hello!
};
```

# 03

```shell

|---(r)eader thread------------|---(w)riter thread-----------|
|    wait for cmap to be ready |                             |
|                              |   create cmap               |
|                              |   update cmap (fill up)     |
|                              |   ready!                    |
|                              |                             |
|    read values from cmap     |   update cmap               |
|    (interval 100ms)          |   (interval 1000ms)         |
|    continue                  |   continue                  |
|    continue                  |   continue                  |
|    continue                  |   continue                  |
|    continue                  |   delete all nodes          |
|    continue...               |   exit                      |
|    untile there is no value  |                             |
|    (sum == 0)                |                             |
|    exit                      |                             |
--------------------------------------------------------------
```

# 04

```shell
$ make
```
 # 05

```shell

$ sudo dmesg -wH
```

# 06

```shell
$ sudo insmod rcucmap.ko
```

```shell
# `dmesg -wH` output
[Sep24 09:06] r: init
[  +0.000007] r: wait...
[  +0.000087] w: init
[  +0.000038] w: updating cmap
[  +0.000003] w: update cmap: 0
[  +0.000001] w: update cmap: 5
[  +0.000001] w: update cmap: 2
[  +0.000001] w: update cmap: 9
[  +0.000001] w: update cmap: 5
[  +0.000001] w: update cmap: 2
[  +0.000000] w: update cmap: 8
[  +0.000001] w: update cmap: 3
[  +0.000001] w: update cmap: 1
[  +0.000000] w: update cmap: 7
[  +0.000001] w: ready
[  +0.103514] r: run
[  +0.000017] r: continue: sum: 45
[  +0.100011] r: continue: sum: 45
[  +0.100018] r: continue: sum: 45
[  +0.100057] r: continue: sum: 45
[  +0.100018] r: continue: sum: 45
[  +0.100015] r: continue: sum: 45
[  +0.100015] r: continue: sum: 45
[  +0.100016] r: continue: sum: 45
[  +0.100020] r: continue: sum: 45
[  +0.100021] r: continue: sum: 45
[  +0.100025] r: continue: sum: 45
[  +0.100070] r: continue: sum: 45
[  +0.100025] r: continue: sum: 45
[  +0.100032] r: continue: sum: 45
[  +0.100033] r: continue: sum: 45
[  +0.100060] r: continue: sum: 45
[  +0.100054] r: continue: sum: 45
[  +0.100030] r: continue: sum: 45
[  +0.100021] r: continue: sum: 45
[  +0.100018] r: continue: sum: 90
[  +0.100021] r: continue: sum: 90
[  +0.100018] r: continue: sum: 90
[  +0.100021] r: continue: sum: 90
[  +0.100019] r: continue: sum: 90
[  +0.100017] r: continue: sum: 90
[  +0.100016] r: continue: sum: 90
[  +0.100025] r: continue: sum: 90
[  +0.100017] r: continue: sum: 90
[  +0.100019] r: continue: sum: 90
[  +0.100018] r: continue: sum: 135
[  +0.100022] r: continue: sum: 135
[  +0.100015] r: continue: sum: 135
[  +0.100015] r: continue: sum: 135
[  +0.100036] r: continue: sum: 135
[  +0.100053] r: continue: sum: 135
[  +0.100020] r: continue: sum: 135
[  +0.100028] r: continue: sum: 135
[  +0.100041] r: continue: sum: 135
[  +0.100021] r: continue: sum: 135
[  +0.096219] w: removing from cmap
[  +0.000004] w: remove cmap: 0
[  +0.000002] w: remove cmap: 5
[  +0.000001] w: remove cmap: 2
[  +0.000001] w: remove cmap: 9
[  +0.000000] w: remove cmap: 5
[  +0.000001] w: remove cmap: 2
[  +0.000001] w: remove cmap: 8
[  +0.000000] w: remove cmap: 3
[  +0.000001] w: remove cmap: 1
[  +0.000000] w: remove cmap: 7
[  +0.000039] w: done
[  +0.003755] r: done: sum == 0


```

# 07

```shell
$ sudo rmmod rcucmap
```

```shell
[ +17.767446] rcucmap: deleting cmap
[  +0.000007] rcucmap: exit

```