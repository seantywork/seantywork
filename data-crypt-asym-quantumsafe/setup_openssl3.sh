#!/bin/bash 

OSSLV="3.5.5"


curl -L "https://github.com/openssl/openssl/releases/download/openssl-$OSSLV/openssl-$OSSLV.tar.gz" -o "openssl-$OSSLV.tar.gz"

tar -zxf "openssl-$OSSLV.tar.gz"

mv "openssl-$OSSLV" "openssl-qs"

cd "openssl-qs"

./config

make

#make test

#sudo make install

#sudo ldconfig /usr/local/lib64/

#mv /usr/bin/openssl /root/

#ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl