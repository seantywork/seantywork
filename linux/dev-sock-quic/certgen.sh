#!/bin/bash

rm -r ./certs/*


echo "root generating...."

openssl genrsa -out ./certs/ca_priv.pem 4096

openssl rsa -in ./certs/ca_priv.pem -outform PEM -pubout -out ./certs/ca_pub.pem

openssl req -x509 -new -key ./certs/ca_priv.pem -days 3650 -out ./certs/ca.pem -subj "/CN=quicroot"

echo "server key pair, csr generating...."

openssl genrsa -out ./certs/server.key.pem 4096

openssl rsa -in ./certs/server.key.pem -outform PEM -pubout -out ./certs/server.pub.pem

openssl req -key ./certs/server.key.pem -new -sha256 -out ./certs/server.csr  -subj "/CN=localhost" 

echo "client key pair, csr generating...."

openssl genrsa -out ./certs/client.key.pem 4096

openssl rsa -in ./certs/client.key.pem -outform PEM -pubout -out ./certs/client.pub.pem

openssl req -key ./certs/client.key.pem -new -sha256 -out ./certs/client.csr  -subj "/CN=client" 


echo "signing requests for server...."

openssl x509 -req -extfile <(printf "subjectAltName = DNS:localhost") -days 365 -in ./certs/server.csr -CA ./certs/ca.pem -CAkey ./certs/ca_priv.pem -CAcreateserial -sha256 -out ./certs/server.crt.pem 

echo "signing requests for client...."

openssl x509 -req -extfile <(printf "subjectAltName = DNS:client") -days 365 -in ./certs/client.csr -CA ./certs/ca.pem -CAkey ./certs/ca_priv.pem -CAcreateserial -sha256 -out ./certs/client.crt.pem 

#sudo /bin/cp -Rf ca.pem /usr/local/share/ca-certificates/quicroot.crt

#sudo update-ca-certificates

echo "done!"