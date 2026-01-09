# CGROUP

```shell
# cgroup 

# check cgroup mount location

mount | grep cgroup2

# if not change kernel parameters in grub to see

# cgroup_no_v1=all

cat /proc/cmdline

# check controllers

cat /sys/fs/cgroup/cgroup.controllers

# add controller , here SOMETHING being cpu 

echo "+$SOMETHING" >> /sys/fs/cgroup/cgroup.subtree_control  

# add sub group

mkdir /sys/fs/cgroup/$SOME_GROUP

# give cpu max

echo "$MAX $PERIOD" > /sys/fs/cgroup/$SOME_GROUP/cpu.max

# revoke group

rmdir /sys/fs/cgroup/$SOME_GROUP


```