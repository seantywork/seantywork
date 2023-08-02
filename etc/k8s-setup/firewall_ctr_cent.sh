#!/bin/bash

firewall-cmd --permanent --add-port=3446/tcp

firewall-cmd --permanent --add-port=6443/tcp

firewall-cmd --permanent --add-port=2379-2380/tcp

firewall-cmd --permanent --add-port=10250/tcp

firewall-cmd --permanent --add-port=10259/tcp

firewall-cmd --permanent --add-port=10257/tcp

firewall-cmd --permanent --add-port=10250/tcp

firewall-cmd --permanent --add-port=30000-32767/tcp

firewall-cmd --permanent --add-port=80/tcp

firewall-cmd --permanent --add-port=443/tcp

firewall-cmd --zone=trusted --add-source=192.168.0.1/24 --permanent

firewall-cmd --zone=trusted --add-source=10.10.0.0/16 --permanent
