#!/bin/bash

rm -r ./certs/*

echo "root generating...."

openssl genrsa -out ./certs/ca_priv.pem 4096

openssl rsa -in ./certs/ca_priv.pem -outform PEM -pubout -out ./certs/ca_pub.pem

openssl req -x509 -new -key ./certs/ca_priv.pem -days 3650 -out ./certs/ca.pem -subj "/CN=localhost_ca"

echo "server key pair, csr generating...."

openssl genrsa -out ./certs/server.key 4096

openssl rsa -in ./certs/server.key -outform PEM -pubout -out ./certs/server.pub

openssl req -key ./certs/server.key -new -sha256 -out ./certs/server.csr  -subj "/CN=localhost" 

echo "signing requests for server...."

openssl x509 -req -extfile <(printf "subjectAltName = DNS:localhost") -days 365 -in ./certs/server.csr -CA ./certs/ca.pem -CAkey ./certs/ca_priv.pem -CAcreateserial -sha256 -out ./certs/server.pem 


echo "done!"