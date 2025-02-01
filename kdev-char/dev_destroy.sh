#!/bin/bash


sudo rm /dev/char_dev_driver
sudo rmmod char_dev_driver


echo "dev node destroyed"