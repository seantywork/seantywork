#!/bin/bash

if [ ! "$EUID" -ne 0 ]
then 
    echo "do not run as root"
    exit 1
fi


if [ ! -d  xdp-tools ]
then
  echo "xdp-tools doesn't exist"
  exit 1
fi

make clean

make

sudo rm -rf /bpf/*.o

sudo mkdir -p /bpf/

sudo /bin/cp -Rf *.o /bpf/

