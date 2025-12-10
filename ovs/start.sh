#!/bin/bash

mkdir -p /usr/local/etc/openvswitch

sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema

sudo /usr/local/share/openvswitch/scripts/ovs-ctl start

sudo ovs-vsctl --no-wait init

# sudo ovs-vswitchd --pidfile --detach --log-file