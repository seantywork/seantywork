#!/bin/bash

sudo apt-get update

sudo apt-get install linux-headers-$(uname -r)

sudo apt-get install kmod 