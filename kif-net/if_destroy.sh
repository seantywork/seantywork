#!/bin/bash


sudo rmmod net_if_driver

sudo dmesg | grep '<0>'

echo "if driver unloaded"