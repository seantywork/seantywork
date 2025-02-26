#!/bin/bash 

sudo apt update 

sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

git clone https://github.com/seantywork/oqs-provider.git

git clone https://github.com/seantywork/liboqs.git

pushd liboqs 

mkdir build 

pushd build 

cmake -GNinja .. 

ninja 

sudo ninja install

popd 

popd 

pushd oqs-provider 

cmake -S . -B _build && cmake --build _build && ctest --test-dir _build && sudo cmake --install _build

popd
