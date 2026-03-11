#!/bin/bash 
virt-install \
  --import \
  --osinfo ubuntu24.04 \
  --name test-00 \
  --ram 4096 \
  --vcpus 4 \
  --disk /var/lib/libvirt/images/ubuntu24-8.qcow2,size=100 \
  --graphics none \
  --network network=test-net \
  --console pty,target.type=virtio \
  --autoconsole text