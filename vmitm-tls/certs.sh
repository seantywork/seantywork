#!/bin/bash 


rm -r ./certs/*

mkdir -p certs

echo "root generating...."

openssl genrsa -out ./certs/ca_priv.pem 4096

openssl rsa -in ./certs/ca_priv.pem -outform PEM -pubout -out ./certs/ca_pub.pem

openssl req -x509 -new -key ./certs/ca_priv.pem -days 3650 -out ./certs/ca.pem -subj "/CN=ca"

echo "server key pair, csr generating...."

openssl genrsa -out ./certs/server_priv.pem 4096

openssl rsa -in ./certs/server_priv.pem -outform PEM -pubout -out ./certs/server_pub.pem

openssl req -key ./certs/server_priv.pem -new -sha256 -out ./certs/server_csr.pem  -subj "/CN=server" 

echo "signing requests for server...."

openssl x509 -req -extfile <(printf "subjectAltName = DNS:server.loc") -days 365 -in ./certs/server_csr.pem -CA ./certs/ca.pem -CAkey ./certs/ca_priv.pem -CAcreateserial -sha256 -out ./certs/server.pem 


echo "done!"