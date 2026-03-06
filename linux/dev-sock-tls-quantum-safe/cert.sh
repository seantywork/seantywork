#!/bin/bash

openssl req -x509 -new -newkey mldsa65 -keyout ca.key.pem -out ca.crt.pem -nodes -subj "/CN=microsoft" -days 3650

openssl genpkey -algorithm mldsa65 -out srv.key.pem

openssl req -new -newkey mldsa65 -keyout srv.key.pem -out srv.csr -nodes -subj "/CN=rules" 

openssl x509 -req -in srv.csr -out srv.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365
