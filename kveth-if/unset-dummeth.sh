#!/bin/bash


sudo ip link set dev dummeth0 down

sudo ip link set dev dummeth1 down

sudo ip addr del 192.168.0.1/24 dev dummeth0

sudo ip addr del 192.168.1.2/24 dev dummeth1



