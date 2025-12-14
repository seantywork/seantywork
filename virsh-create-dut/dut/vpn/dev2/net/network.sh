#!/bin/bash 

set -exo pipefail

sudo ip netns add net1
sudo ip link set dev enp7s3 netns net1
sudo ip addr add 192.168.101.21/24 dev ens3
sudo ip link set dev ens3 up
