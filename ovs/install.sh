#!/bin/bash

sudo apt update 
sudo apt install build-essential make autoconf libtool
git clone https://github.com/openvswitch/ovs.git

cd ovs 

git switch -c myovs origin/branch-3.6

./boot.sh 

./configure

make 

sudo make install

