#!/bin/bash


# delete rules 

sudo iptables -F 

sudo iptables -t nat -F

sudo ip netns del net1

sudo ip netns del net2