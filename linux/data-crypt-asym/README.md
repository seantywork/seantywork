# crypt-asym

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-crypt-asym)












# misc

```shell
# rsa certgen

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

```


```shell
# ec certgen


rm -r ./certs/*

mkdir ./certs

echo "root generating...."

openssl genpkey -algorithm ed25519 -out ./certs/ca_priv.pem 

openssl pkey -in ./certs/ca_priv.pem -outform PEM -pubout -out ./certs/ca_pub.pem

openssl req -x509 -new -key ./certs/ca_priv.pem -days 3650 -out ./certs/ca.pem -subj "/CN=root"

echo "server key pair, csr generating...."

openssl genpkey -algorithm ed25519 -out ./certs/server.key 

openssl pkey -in ./certs/server.key -outform PEM -pubout -out ./certs/server.pub

openssl req -key ./certs/server.key -new -sha256 -out ./certs/server.csr  -subj "/CN=localhost" 

echo "signing requests for server...."

openssl x509 -req -extfile <(printf "subjectAltName = DNS:localhost") -days 365 -in ./certs/server.csr -CA ./certs/ca.pem -CAkey ./certs/ca_priv.pem -CAcreateserial -sha256 -out ./certs/server.pem 


echo "done!"


```


```shell
# verify

openssl verify -CAfile ./certs/ca.pem ./certs/server.pem

# read 

openssl x509 -in ./certs/server.pem -text -noout

```

```shell
# server
openssl s_server -key s_priv.pem -cert srv.crt.pem -CAfile ca.crt.pem -port 9999
# client
openssl s_client -connect localhost:9999 -key c_priv.pem -cert cli.crt.pem -CAfile ca.crt.pem

```


