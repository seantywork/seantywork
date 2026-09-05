#!/bin/bash


echo "gen ca..."

openssl genrsa -out ca_priv.pem 4096

openssl rsa -in ca_priv.pem -outform PEM -pubout -out ca_pub.pem

openssl req -x509 -new -key ca_priv.pem -days 365 -out ca.crt.pem -subj "/CN=socializeca"


echo "gen server..."

openssl genrsa -out server_priv.pem 4096

openssl rsa -in server_priv.pem -outform PEM -pubout -out server_pub.pem

openssl req -key server_priv.pem -new -sha256 -out server.csr -subj "/CN=server.test"

echo "signing server..."

openssl  x509 -req -extfile <(printf "subjectAltName = DNS:server.test") -days 180 -in server.csr -CA ca.crt.pem -CAkey ca_priv.pem -CAcreateserial -sha256 -out server.crt.pem


echo "gen sub1..."

openssl genrsa -out sub_priv1.pem 4096

openssl rsa -in sub_priv1.pem -outform PEM -pubout -out sub_pub1.pem

openssl req -key sub_priv1.pem -new -sha256 -out sub1.csr -subj "/CN=sub1.test"

echo "gen sub2..."

openssl genrsa -out sub_priv2.pem 4096

openssl rsa -in sub_priv2.pem -outform PEM -pubout -out sub_pub2.pem

openssl req -key sub_priv2.pem -new -sha256 -out sub2.csr -subj "/CN=sub2.test"

echo "signing sub1..."

openssl  x509 -req -extfile <(printf "subjectAltName = DNS:sub1.test") -days 180 -in sub1.csr -CA ca.crt.pem -CAkey ca_priv.pem -CAcreateserial -sha256 -out sub1.crt.pem

echo "signiing sub2..."

openssl  x509 -req -extfile <(printf "subjectAltName = DNS:sub2.test") -days 180 -in sub2.csr -CA ca.crt.pem -CAkey ca_priv.pem -CAcreateserial -sha256 -out sub2.crt.pem


/bin/cp -Rf *.pem ./tls/

rm -rf *.pem *.srl *.csr