#!/bin/bash

set -x

sudo ip netns del vnet0
sudo ip netns del vnet1
sudo ip netns del vnet2