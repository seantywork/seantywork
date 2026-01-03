#!/bin/bash

set -exo pipefail

sudo apt update 
sudo apt install -y build-essential make autoconf libtool libssl-dev
git clone https://github.com/openvswitch/ovs.git

cd ovs 

git switch -c myovs origin/branch-3.6

./boot.sh 

./configure --enable-ssl

make 

sudo make install

