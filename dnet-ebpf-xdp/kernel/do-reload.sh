#!/bin/bash

if [ -z "$1" ]
then

    echo "feed xdp prog name"

    exit 1

fi

sudo xdp-loader unload -a veth1

sudo xdp-loader load -m skb -s "$1" veth1 "$1.o"