#!/bin/bash


echo "gen ca..."

openssl genrsa -out ca.key 4096

openssl rsa -in ca.key -outform PEM -pubout -out ca.pub

openssl req -x509 -new -key ca.key -days 365 -out ca.crt -subj "/CN=socializeca"


echo "gen server..."

openssl genrsa -out server.key 4096

openssl rsa -in server.key -outform PEM -pubout -out server.pub

openssl req -key server.key -new -sha256 -out server.csr -subj "/CN=server.test"

echo "signing server..."

openssl  x509 -req -extfile <(printf "subjectAltName = DNS:server.test") -days 180 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -out server.crt

echo "gen sub1..."

openssl genrsa -out client.key 4096

openssl rsa -in client.key -outform PEM -pubout -out client.pub

openssl req -key client.key -new -sha256 -out client.csr -subj "/CN=client.test"

echo "signing sub1..."

openssl  x509 -req -extfile <(printf "subjectAltName = DNS:client.test") -days 180 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -out client.crt

/bin/cp -Rf *.crt ./tls/

/bin/cp -Rf *.key ./tls/


rm -rf *.pem *.srl *.csr *.crt *.key *.pub