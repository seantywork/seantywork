#!/bin/bash



SERVER=1

LINE_27=$(cat /sys/kernel/debug/gpio | grep GPIO27)


PIN_IN=$(echo $LINE_27 | awk -F "-" '{print $2}' | awk -F "(" '{print $1}')


echo $PIN_IN 



insmod kgpiosock.ko server=$SERVER pin_s0=$PIN_IN 