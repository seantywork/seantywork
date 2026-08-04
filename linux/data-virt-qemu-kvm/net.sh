#!/bin/bash


cat << EOF > net1.xml
<network>
  <name>net1</name>
  <forward mode='nat'/>
  <bridge name='net1' stp='on' delay='0'/>
  <domain name='net1'/>
  <ip address='192.168.101.1' netmask='255.255.255.0'>
  </ip>
</network>
EOF


sudo virsh net-define net1.xml