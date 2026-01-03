#!/bin/bash

set -exo pipefail

ovs_setup(){
    sudo ovs-vsctl add-br ovs-br0
    sudo ovs-vsctl add-port ovs-br0 veth11
    sudo ovs-vsctl add-port ovs-br0 veth21
    sudo ip link set up veth11
    sudo ip link set up veth21
    sudo ip link set ovs-br0 up   
}

ovs_setup
