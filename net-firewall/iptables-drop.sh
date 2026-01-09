#!/bin/bash

sudo ip netns exec vnet0 iptables -A INPUT -p tcp --dport 9999 -j DROP 