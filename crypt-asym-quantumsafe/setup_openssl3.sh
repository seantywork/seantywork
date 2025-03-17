#!/bin/bash 

OSSLV="openssl-3.4.1"


curl -L "https://github.com/openssl/openssl/releases/download/openssl-$OSSLV/openssl-$OSSLV.tar.gz" -o "openssl-$OSSLV.tar.gz"

tar -zxf "openssl-$OSSLV.tar.gz"

cd "openssl-$OSSLV"

./config

make

make test

sudo make install

sudo ldconfig /usr/local/lib64/

#mv /usr/bin/openssl /root/

#ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl