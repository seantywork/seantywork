#!/bin/bash 

CTLOUT="0"
CTLIN="0"
DEV="n"
CTLOUT_LINE=""
CTLIN_LINE=""

if [ ! -f ./ins.conf ]
then
    echo "ins.con not found"
    exit 1
fi

source ./ins.conf

if [[ "$CTLOUT" == "0" ]]
then 
    DEV="y"
fi

if [[ "$CTLIN" == "0" ]]
then 
    DEV="y"
fi

if [[ "$DEV" == "n" ]]
then
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


else 
    if [[ "$CTLOUT" == "0" ]]
    then 
        CTLIN_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLIN)
        if [[ "$CTLIN_LINE" == "" ]]
        then 
            echo "couldn't find $CTLIN in devmode"
            exit 1
        fi
        CTLIN_LINE=$(echo $CTLIN_LINE | cut -d "-" -f 2)
        CTLIN_LINE=$(echo $CTLIN_LINE | cut -d " " -f 1)
        CTLOUT_LINE="$CTLOUT"
    fi

    if [[ "$CTLIN" == "0" ]]
    then 
        CTLOUT_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLOUT)
        if [[ "$CTLOUT_LINE" == "" ]]
        then 
            echo "couldn't find $CTLOUT"
            exit 1
        fi
        CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d "-" -f 2)
        CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d " " -f 1)
        CTLIN_LINE="$CTLIN"
    fi
fi

echo "CTL OUT: $CTLOUT = $CTLOUT_LINE"
echo "CTL IN : $CTLIN = $CTLIN_LINE"

insmod kgpio_irqsk.ko gpio_ctl_o=$CTLOUT_LINE gpio_ctl_i=$CTLIN_LINE

