#!/bin/bash

echo "creating interface..."

sudo ip netns add net1

sudo ip link add dev veth11 type veth peer name veth12 netns net1

sudo ip link set up veth11

sudo ip netns exec net1 ip link set up veth12

sudo ip addr add 192.168.62.5/24 dev veth11

sudo ip netns exec net1 ip addr add 192.168.62.6/24 dev veth12

rm -rf *.txt

END=1000000

echo "creating $END entries..."

for i in $(seq 1 $END)
do 
    echo "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf" >> test.txt 
done
echo "exit" >> test.txt

sudo ip netns exec net1 ./ncat.out -l 192.168.62.6 9999 

sleep 1

echo "running test..."

time ./ncat.out 192.168.62.6 9999 < test.txt

echo "test completed"

sleep 1

sudo pkill ncat.out 

sudo ip netns del net1
