#!/bin/bash

set -exo pipefail

setup(){
    sudo ip netns add net1
    sudo ip netns add net2
    sudo ip link add dev veth11 type veth peer name veth12 netns net1
    sudo ip link add dev veth21 type veth peer name veth22 netns net2
    sudo ip netns exec net1 ip addr add 192.168.64.12/24 dev veth12
    sudo ip netns exec net2 ip addr add 192.168.64.22/24 dev veth22
    sudo ip netns exec net1 ip link set veth12 up
    sudo ip netns exec net2 ip link set veth22 up
    sudo ip netns exec net1 ip link set lo up
    sudo ip netns exec net2 ip link set lo up
    sudo sysctl -w net.ipv4.ip_forward=1
}



gen_cert(){
    mkdir -p controller/certs
    mkdir -p switch/certs
    echo "root generating...."
    openssl genrsa -out ./ca.key.pem 2048
    openssl req -x509 -new -key ./ca.key.pem -days 3650 -out ./ca.cert.pem -subj "/CN=root"
    echo "server key pair, csr generating...."
    openssl genrsa -out ./controller/certs/server.key.pem 2048
    openssl req -key ./controller/certs/server.key.pem -new -sha256 -out ./controller/certs/server.csr  -subj "/CN=controller.openflow" 
    echo "signing requests for server...."
    openssl x509 -req -days 365 -in ./controller/certs/server.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -sha256 -out ./controller/certs/server.cert.pem 
    /bin/cp -Rf ca.cert.pem ./controller/certs
    echo "client key pair, csr generating...."
    openssl genrsa -out ./switch/certs/client.key.pem 2048
    openssl req -key ./switch/certs/client.key.pem -new -sha256 -out ./switch/certs/client.csr  -subj "/CN=switch.openflow" 
    echo "signing requests for server...."
    openssl x509 -req -days 365 -in ./switch/certs/client.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -sha256 -out ./switch/certs/client.cert.pem
    /bin/cp -Rf ca.cert.pem ./switch/certs
    rm -rf *.pem 
    echo "done!"
}

cleanup(){
    sudo ip netns del net1
    sudo ip netns del net2
}

#setup
gen_cert
#cleanup