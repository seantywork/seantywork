
# debian

```shell
# /etc/network/interfaces

# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto enp1s0
iface enp1s0 inet dhcp

iface enp7s0 inet static
    address 192.168.101.25
    netmask 255.255.255.0
    gateway 192.168.101.1

#auto br0
#iface br0 inet static
#    address 192.168.101.25/24
#    gateway 192.168.101.1
#    bridge_ports enp1s0 enp2s0
#    up /usr/sbin/brctl stp br0 on|off

```

# ubuntu

```shell
# /etc/netplan/00-config.yaml

network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0:
      dhcp4: true
    enp7s0:
      dhcp4: false
      addresses: [192.168.101.25/24]
      routes:
      - to: 192.168.101.0/24
        via: 192.168.101.1
    
#  bridges:
#    br0:
#      interfaces: [enp1s0, enp7s0]
#      dhcp4: false
#      addresses: [192.168.101.25/24, 10.168.0.26/24]
#      routes:
#        - to: default
#          via: 192.168.101.1
#      parameters:
#        stp: false
```


# fedora

```shell
# Show all connection profiles

nmcli con show

# Change Wired Connection 1 from DHCP to static
nmcli con mod "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses "192.168.1.100/24" \
  ipv4.gateway "192.168.1.1" \
  ipv4.dns "8.8.8.8,1.1.1.1"

# Apply the change
nmcli con up "Wired connection 1"

# Create a new connection named "static-eth0"
# no default route
sudo nmcli con add \
    type ethernet  \
    con-name "enp1s0"   \
    ifname enp1s0   \
    ipv4.method manual \
    ipv4.addresses "192.168.101.64/24"  \
    ipv4.gateway "192.168.101.1" \
    ipv4.routes "192.168.101.0/24" \
    ipv4.never-default true   

# Activate it
nmcli con up "static-eth0"

# dhcp
nmcli con mod "static-eth0" ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns ""
nmcli con up "static-eth0"

# Add a static route for 10.0.0.0/8
nmcli con mod "static-eth0" +ipv4.routes "10.0.0.0/8 192.168.1.254"
nmcli con up "static-eth0"

# Add a second address to the connection
nmcli con mod "static-eth0" +ipv4.addresses "192.168.1.101/24"
nmcli con up "static-eth0"

# delete conn
nmcli con delete enp1s0

# upon manual modification at
# /etc/NetworkManager/system-connections
sudo nmcli con reload
sudo nmcli con up $CONNNAME
```