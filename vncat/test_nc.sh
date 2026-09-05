#!/bin/bash

echo "creating interface..."

sudo ip netns add net1

sudo ip link add dev veth11 type veth peer name veth12 netns net1

sudo ip link set up veth11

sudo ip netns exec net1 ip link set up veth12

sudo ip addr add 192.168.62.5/24 dev veth11

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth12


END=1000000

echo "creating $END entries..."

if ! [ -f "./test.txt" ]
then
    for i in $(seq 1 $END)
    do 
        echo "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf" >> test.txt 
    done
    echo "exit" >> test.txt
else 

    echo "test.txt exists"
fi

sudo ip netns exec net1 nc -l 192.168.62.6 9999 > /dev/null 2>&1 &

sleep 1

echo "running test..."

time nc 192.168.62.6 9999 < test.txt

echo "test completed"

sleep 1

sudo pkill nc

sudo ip netns del net1
