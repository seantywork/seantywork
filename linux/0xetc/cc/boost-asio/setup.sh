#!/bin/bash


BOOST_VERSION="1_81_0"

rm -rf boost_*



# curl -L "https://boostorg.jfrog.io/artifactory/main/release/1.60.0/source/boost_$BOOST_VERSION.tar.gz" -o "boost_$BOOST_VERSION.tar.gz"

curl -L "https://sourceforge.net/projects/boost/files/boost/1.81.0/boost_$BOOST_VERSION.tar.gz/download" -o "boost_$BOOST_VERSION.tar.gz"


tar -xzf "boost_$BOOST_VERSION.tar.gz"


pushd "boost_$BOOST_VERSION"

./bootstrap.sh --prefix=./build

./b2 install

popd