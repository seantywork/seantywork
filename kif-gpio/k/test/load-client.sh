#!/bin/bash

SERVER=0

LINE_18=$(cat /sys/kernel/debug/gpio | grep GPIO18)


PIN_OUT=$(echo $LINE_18 | awk -F "-" '{print $2}' | awk -F "(" '{print $1}')


echo $PIN_OUT

insmod kgpiosock.ko server=$SERVER pin_c0=$PIN_OUT