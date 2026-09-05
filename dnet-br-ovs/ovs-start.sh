#!/bin/bash

set -exo pipefail

mkdir -p /usr/local/etc/openvswitch

pushd ovs

sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema

popd

sudo /usr/local/share/openvswitch/scripts/ovs-ctl start

sudo ovs-vsctl --no-wait init

