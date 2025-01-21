#!/bin/bash

netstat -anp | grep hack

nmap -sS 127.0.0.1 -p-