#!/bin/bash


virsh net-destroy netctl1
virsh net-destroy netctl2
virsh net-destroy net1
virsh net-destroy net2

virsh net-undefine netctl1
virsh net-undefine netctl2
virsh net-undefine net1
virsh net-undefine net2

virsh net-define host-vpn/net/netctl1.xml
virsh net-define host-vpn/net/netctl2.xml
virsh net-define host-vpn/net/net1.xml
virsh net-define host-vpn/net/net2.xml


virsh net-start netctl1
virsh net-start netctl2
virsh net-start net1
virsh net-start net2

# virsh net-autostart net1ctl
# virsh net-autostart net2ctl
# virsh net-autostart net1
# virsh net-autostart net2

sudo /bin/cp -Rf /var/lib/libvirt/images/ubuntu24.04-4.qcow2 /var/lib/libvirt/images/dev1-4.qcow2

sudo /bin/cp -Rf /var/lib/libvirt/images/ubuntu24.04-2.qcow2 /var/lib/libvirt/images/dev2-2.qcow2


virsh define host-vpn/dev1-4.xml

virsh define host-vpn/dev2-2.xml

sudo sysctl -w net.ipv4.ip_forward=1