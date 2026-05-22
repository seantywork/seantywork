#!/bin/bash

set -x

sudo ip netns del vnet
sudo ip xfrm state flush
sudo ip xfrm policy flush
sudo ip rule del preference 100
sudo ip route del 10.168.66.0/24 dev kxfrm0