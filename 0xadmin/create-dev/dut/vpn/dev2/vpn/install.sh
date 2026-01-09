#!/bin/bash 

set -exo pipefail 

scp seantywork@192.168.101.25:/tmp/dev2.vpn.tar.gz .

tar xzf dev2.vpn.tar.gz 

sudo /bin/cp -Rf swanctl.conf /etc/swanctl/swanctl.conf
sudo /bin/cp -Rf ca.cert.pem /etc/swanctl/x509ca/
sudo /bin/cp -Rf client.cert.pem /etc/swanctl/x509
sudo /bin/cp -Rf client.key.pem /etc/swanctl/private

sudo systemctl restart strongswan
