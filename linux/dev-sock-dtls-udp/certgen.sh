#!/bin/bash

rm -r ./client/certs/*

rm -r ./server/certs/*

echo "root generating...."

openssl genrsa -out ./client/certs/ca_priv.pem 4096

openssl rsa -in ./client/certs/ca_priv.pem -outform PEM -pubout -out ./client/certs/ca_pub.pem

openssl req -x509 -new -key ./client/certs/ca_priv.pem -days 3650 -out ./client/certs/ca.pem -subj "/CN=root"

echo "server key pair, csr generating...."

openssl genrsa -out ./server/certs/server.key 4096

openssl rsa -in ./server/certs/server.key -outform PEM -pubout -out ./server/certs/server.pub

openssl req -key ./server/certs/server.key -new -sha256 -out ./server/certs/server.csr  -subj "/CN=localhost" 

echo "signing requests for server...."

openssl x509 -req -extfile <(printf "subjectAltName = DNS:localhost") -days 365 -in ./server/certs/server.csr -CA ./client/certs/ca.pem -CAkey ./client/certs/ca_priv.pem -CAcreateserial -sha256 -out ./server/certs/server.pem 


echo "done!"