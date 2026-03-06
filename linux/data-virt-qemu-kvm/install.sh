#!/bin/bash

THIS_USER=""
if [ -z "$1" ]; then
        echo "needs user"
        exit 1
fi
THIS_USER="$1"

sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils -y
sudo adduser $THIS_USER libvirt
sudo adduser $THIS_USER kvm
sudo systemctl enable --now libvirtd