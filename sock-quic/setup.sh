#!/bin/bash 


sudo apt-get update
sudo apt-get install cmake build-essential liblttng-ust-dev lttng-tools


git clone https://github.com/seantywork/msquic.git 


mkdir -p msquic/build

pushd msquic

git submodule update --init --recursive

pushd build

cmake ..

make 

popd

popd

