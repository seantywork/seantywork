#!/bin/bash 

source ./ins.conf

CTLOUT_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLOUT) 
CTLIN_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLIN)


if [[ "$CTLOUT_LINE" == "" ]]
then 
    echo "couldn't find $CTLOUT"
    exit 1
fi

if [[ "$CTLIN_LINE" == "" ]]
then 
    echo "couldn't find $CTLIN"
    exit 1
fi

CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d "-" -f 2)
CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d " " -f 1)

CTLIN_LINE=$(echo $CTLIN_LINE | cut -d "-" -f 2)
CTLIN_LINE=$(echo $CTLIN_LINE | cut -d " " -f 1)

echo "CTL OUT: $CTLOUT = $CTLOUT_LINE"
echo "CTL IN : $CTLIN = $CTLIN_LINE"

insmod ksock_gpio.ko gpio_ctl_o=$CTLOUT_LINE gpio_ctl_i=$CTLIN_LINE

