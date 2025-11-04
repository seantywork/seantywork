#!/bin/bash

sudo insmod ./mem_storage.ko
dev="mem_storage"
major="$(grep "$dev" /proc/devices | cut -d ' ' -f 1)"
#sudo mknod "/dev/$dev" c "$major" 0
sudo mknod "./user/$dev" c "$major" 0
echo "dev node created"
#echo "/dev/$dev"
echo "./user/$dev"