#!/bin/bash

set -x

sudo ip netns exec vnet pkill -9 espinudp_enable
sudo pkill -9 espinudp_enable
sudo ip netns del vnet
sudo ip xfrm state flush
sudo ip xfrm policy flush
sudo ip rule del preference 100
