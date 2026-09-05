#!/bin/bash

virt-install \
  --import \
  --osinfo ubuntu25.10 \
  --name dev1 \
  --ram 8192 \
  --vcpus 8 \
  --disk /var/lib/libvirt/images/dev1.qcow2,size=64 \
  --graphics none \
  --network network=net1 \
  --network network=default \
  --console pty,target.type=virtio \
  --autoconsole text
