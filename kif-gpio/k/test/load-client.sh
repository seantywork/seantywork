#!/bin/bash

SERVER=0

LINE_24=$(cat /sys/kernel/debug/gpio | grep GPIO24)


PIN_OUT=$(echo $LINE_24 | awk -F "-" '{print $2}' | awk -F "(" '{print $1}')


echo $PIN_OUT

insmod kgpiosock.ko server=$SERVER pin_c0=$PIN_OUT