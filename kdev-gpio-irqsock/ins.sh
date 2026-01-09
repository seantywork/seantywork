#!/bin/bash 

CTLOUT="0"
DATAOUT="0"
CTLIN="0"
DATAIN="0"
DEV="n"
CTLOUT_LINE=""
DATAOUT_LINE=""
CTLIN_LINE=""
DATAIN_LINE=""

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
    DATAOUT_LINE=$(cat /sys/kernel/debug/gpio | grep $DATAOUT) 
    CTLIN_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLIN)
    DATAIN_LINE=$(cat /sys/kernel/debug/gpio | grep $DATAIN)

    if [[ "$CTLOUT_LINE" == "" ]]
    then 
        echo "couldn't find $CTLOUT"
        exit 1
    fi


    if [[ "$DATAOUT_LINE" == "" ]]
    then 
        echo "couldn't find $DATAOUT"
        exit 1
    fi

    if [[ "$CTLIN_LINE" == "" ]]
    then 
        echo "couldn't find $CTLIN"
        exit 1
    fi


    if [[ "$DATAIN_LINE" == "" ]]
    then 
        echo "couldn't find $DATAIN"
        exit 1
    fi

    CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d "-" -f 2)
    CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d " " -f 1)
    DATAOUT_LINE=$(echo $DATAOUT_LINE | cut -d "-" -f 2)
    DATAOUT_LINE=$(echo $DATAOUT_LINE | cut -d " " -f 1)

    CTLIN_LINE=$(echo $CTLIN_LINE | cut -d "-" -f 2)
    CTLIN_LINE=$(echo $CTLIN_LINE | cut -d " " -f 1)
    DATAIN_LINE=$(echo $DATAIN_LINE | cut -d "-" -f 2)
    DATAIN_LINE=$(echo $DATAIN_LINE | cut -d " " -f 1)


else 
    if [[ "$CTLOUT" == "0" ]]
    then 
        CTLIN_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLIN)
        DATAIN_LINE=$(cat /sys/kernel/debug/gpio | grep $DATAIN)
        if [[ "$CTLIN_LINE" == "" ]]
        then 
            echo "couldn't find $CTLIN in devmode"
            exit 1
        fi
        if [[ "$DATAIN_LINE" == "" ]]
        then 
            echo "couldn't find $DATAIN"
            exit 1
        fi
        CTLIN_LINE=$(echo $CTLIN_LINE | cut -d "-" -f 2)
        CTLIN_LINE=$(echo $CTLIN_LINE | cut -d " " -f 1)
        DATAIN_LINE=$(echo $DATAIN_LINE | cut -d "-" -f 2)
        DATAIN_LINE=$(echo $DATAIN_LINE | cut -d " " -f 1)
        CTLOUT_LINE="$CTLOUT"
        DATAOUT_LINE="$DATAOUT"
    fi

    if [[ "$CTLIN" == "0" ]]
    then 
        CTLOUT_LINE=$(cat /sys/kernel/debug/gpio | grep $CTLOUT)
        DATAOUT_LINE=$(cat /sys/kernel/debug/gpio | grep $DATAOUT) 
        if [[ "$CTLOUT_LINE" == "" ]]
        then 
            echo "couldn't find $CTLOUT"
            exit 1
        fi
        if [[ "$DATAOUT_LINE" == "" ]]
        then 
            echo "couldn't find $DATAOUT"
            exit 1
        fi
        CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d "-" -f 2)
        CTLOUT_LINE=$(echo $CTLOUT_LINE | cut -d " " -f 1)
        DATAOUT_LINE=$(echo $DATAOUT_LINE | cut -d "-" -f 2)
        DATAOUT_LINE=$(echo $DATAOUT_LINE | cut -d " " -f 1)
        CTLIN_LINE="$CTLIN"
        DATAIN_LINE="$DATAIN"
    fi
fi

echo "CTL OUT: $CTLOUT = $CTLOUT_LINE"
echo "DATA OUT: $DATAOUT = $DATAOUT_LINE"
echo "CTL IN : $CTLIN = $CTLIN_LINE"
echo "DATA IN : $DATAIN = $DATAIN_LINE"

insmod kgpio_irqsk.ko gpio_ctl_o=$CTLOUT_LINE gpio_data_o=$DATAOUT_LINE gpio_ctl_i=$CTLIN_LINE gpio_data_i=$DATAIN_LINE

if [[ "$DEV" == "n" ]]
then

    echo "IF ADDR: $IF_ADDR"
    ip addr add $IF_ADDR dev geth0

    ip link set dev geth0 up
fi 