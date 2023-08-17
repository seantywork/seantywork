#!/bin/bash

apt update

apt install -y nfs-kernel-server

apt install -y nfs-common

apt install -y jq

mkdir -p /kw_data

chown -R root:root /kw_data

chmod -R 777 /kw_data



local_ip=$1

IP=$local_ip

cat << EOF > /etc/exports

/kw_data $IP/24(rw,sync,no_subtree_check,no_root_squash) 10.10.0.0/16(rw,sync,no_subtree_check,no_root_squash)

EOF

exportfs -a

systemctl restart nfs-kernel-server