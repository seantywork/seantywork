#!/bin/bash 

LIBOQSV="0.12.0"
OQSPROVV="0.8.0"

rm -rf liboqs* oqs-provider* *.tar.gz

sudo apt update 

sudo apt install astyle cmake gcc ninja-build python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind ca-certificates

curl -L https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$LIBOQSV.tar.gz -o "$LIBOQSV.tar.gz"


# curl -L https://github.com/open-quantum-safe/oqs-provider/archive/refs/tags/$OQSPROVV.tar.gz -o "$OQSPROVV.tar.gz"


tar xzf $LIBOQSV.tar.gz

#tar xzf $OQSPROVV.tar.gz

mv "liboqs-$LIBOQSV" liboqs

#mv "oqs-provider-$OQSPROVV" oqs-provider

pushd liboqs

mkdir build 

pushd build 

cmake -GNinja .. 

ninja 

sudo ninja install

popd 

popd 

#pushd oqs-provider

#cmake -S . -B _build && cmake --build _build && ctest --test-dir _build && sudo cmake --install _build

#popd
