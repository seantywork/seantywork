#!/bin/bash


sudo ip addr add 192.168.0.1/24 dev dummeth0

sudo ip addr add 192.168.1.2/24 dev dummeth1

sudo ip link set dev dummeth0 up

sudo ip link set dev dummeth1 up

