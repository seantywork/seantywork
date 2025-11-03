#!/bin/bash

sudo insmod ./user_value.ko
dev="user_value"
major="$(grep "$dev" /proc/devices | cut -d ' ' -f 1)"
sudo mknod "/dev/$dev" c "$major" 0

echo "dev node created"
echo "/dev/$dev"