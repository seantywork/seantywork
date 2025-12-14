#!/bin/bash


SCONFIG="authorityKeyIdentifier = keyid,issuer:always\n" && \
SCONFIG="${SCONFIG}basicConstraints = CA:FALSE\n" && \
SCONFIG="${SCONFIG}keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n" && \
SCONFIG="${SCONFIG}extendedKeyUsage = serverAuth\n" 

CCONFIG="authorityKeyIdentifier = keyid,issuer:always\n" && \
CCONFIG="${CCONFIG}basicConstraints = CA:FALSE\n" && \
CCONFIG="${CCONFIG}keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n" && \
CCONFIG="${CCONFIG}extendedKeyUsage = clientAuth\n" 


openssl genrsa -out ca_priv.pem 4096
openssl rsa -in ca_priv.pem -outform PEM -pubout -out ca_pub.pem
openssl req -x509 -new -key ca_priv.pem -days 365 -out ca.cert.pem -subj "/CN=dev1ca"

openssl genrsa -out server.key.pem 4096
openssl rsa -in server.key.pem -outform PEM -pubout -out ser_pub.pem
openssl req -key server.key.pem -new -sha256 -out server.csr -subj "/CN=dev1server"
openssl x509 -req -days 180 -in server.csr -extfile <(printf "${SCONFIG}") -CA ca.cert.pem -CAkey ca_priv.pem -CAcreateserial -sha256 -out server.cert.pem 

openssl genrsa -out client.key.pem 4096
openssl rsa -in client.key.pem -outform PEM -pubout -out cli_pub.pem
openssl req -key client.key.pem -new -sha256 -out client.csr -subj "/CN=dev1client"
openssl x509 -req -days 180 -in client.csr -extfile <(printf "${CCONFIG}") -CA ca.cert.pem -CAkey ca_priv.pem -CAcreateserial -sha256 -out client.cert.pem 

sudo /bin/cp -Rf swanctl.conf /etc/swanctl/swanctl.conf
sudo /bin/cp -Rf ca.cert.pem /etc/swanctl/x509ca/
sudo /bin/cp -Rf server.cert.pem /etc/swanctl/x509
sudo /bin/cp -Rf server.key.pem /etc/swanctl/private

tar czf dev2.vpn.tar.gz ca.cert.pem client.cert.pem client.key.pem

sudo cp dev2.vpn.tar.gz /tmp/
sudo chmod 777 /tmp/dev2.vpn.tar.gz 

sudo systemctl restart strongswan