#!/bin/bash

sudo insmod ./char_dev_driver.ko
dev="char_dev_driver"
major="$(grep "$dev" /proc/devices | cut -d ' ' -f 1)"
sudo mknod "/dev/$dev" c "$major" 0

echo "dev node created"
echo "/dev/$dev"