#!/bin/bash

sudo dnf install nfs-utils



sudo systemctl start nfs-server.service


sudo systemctl enable --now nfs-server.service


## /etc/exports

## exportfs -a
