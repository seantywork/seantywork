#!/bin/bash 

OSSLV="3.3.3"

cd /usr/src

wget "https://github.com/openssl/openssl/releases/download/openssl-$OSSLV/openssl-$OSSLV.tar.gz" -O "openssl-$OSSLV.tar.gz"

tar -zxf "openssl-$OSSLV.tar.gz"

cd "openssl-$OSSLV"

./config

make

make test

make install

ldconfig /usr/local/lib64/

#mv /usr/bin/openssl /root/

#ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl