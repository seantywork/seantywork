#!/bin/bash

rm -rf build

mkdir -p build


pushd build

cmake ..

make

mv *.out ..

popd

rm -rf build