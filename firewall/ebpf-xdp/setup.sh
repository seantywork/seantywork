#!/bin/bash


sudo apt update

sudo apt install clang llvm libelf-dev libpcap-dev libc6-dev-i386 m4

rm -rf xdp-tools

git clone https://github.com/xdp-project/xdp-tools


cd xdp-tools

./configure

make

sudo make install

cd lib/libbpf/src

sudo make install


