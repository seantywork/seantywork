#!/bin/bash

set -exo pipefail

sudo ip netns del net1 
sudo ip netns del net2
sudo ip link del br0
