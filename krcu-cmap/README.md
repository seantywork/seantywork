# krcu-cmap

- source: [linuxyz/krcu-cmap](https://github.com/seantywork/linuxyz/tree/main/krcu-cmap)
- date: 2509-24

In user space on Linux, we can utilize pthread_rwlock to design a read-heavy data structure.

A similar thing in the Linux kernel space is called `rcu`, a shorthand for "read, copy, update".

Full documentation on it is [here](https://www.kernel.org/doc/html/next/RCU/whatisRCU.html)

However, with pthread_rwlock in mind, it could be a little bit puzzling (at least it was for me) \
to grasp the proper use and order of apis unlike in the case of \
pthread_rwlock where you simply call *_rdlock on read and *_wrlock \
on update

Reading the docs wasn't enough for me.

So I did the thing when I'm confused about the concept of multi-threading \
and syncing mechanism: \
**Building a concurrent map example!**

Here, this is the outlay of this example.


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
However, in this case, our `node` data structure here \
contains the magic element

```c
struct node {
    int key;
    int value;
	struct list_head _node; 
	struct rcu_head _rcu; // <----- hello!
};
```

With all these, our scenario will flow like the diagram below.
The critical part to look for (in my opinion) is \
`delete all nodes` part from writer thread.

If this `rcu` thing cannot guarantee the basic functionality\
we expect from things such as `pthread_rwlock`, then this part\
will cause the GD kernel panic.

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

Now, let's compile the kernel module.

```shell
$ make
```
Pop up another terminal, and use `dmesg` command to follow.

```shell

$ sudo dmesg -wH
```

Load the kernel module with `insmod` command. \
As soon as you do this, `dmesg` will output the result \
described in the diagram above.

```shell
$ sudo insmod rcucmap.ko
```

```shell
# `dmesg -wH` outpu
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

As you can see, the program is working as expected and (thank god) \
there is no kernel panic!

Pleased, unload the kernel module.

```shell
$ sudo rmmod rcucmap
```

```shell
[ +17.767446] rcucmap: deleting cmap
[  +0.000007] rcucmap: exit

```