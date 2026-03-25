# crypt-asym

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-crypt-asym)

In this directory, I'm showcasing basic \
asymmetric cryptography functionalites provided by \
(OpenSSL)[https://www.openssl.org/], which include \
`RSA` and `prime256v1` based key generation, key exchange, \
digital signature, and certificate generation with TLS communication \
based on it.

Below is the description of the environment I'm running this.
```shell

$ lscpu
Architecture:                x86_64
  CPU op-mode(s):            32-bit, 64-bit
  Address sizes:             39 bits physical, 48 bits virtual
  Byte Order:                Little Endian
CPU(s):                      4
  On-line CPU(s) list:       0-3
Vendor ID:                   GenuineIntel
  Model name:                Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz

$ cat /etc/os-release 
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo

$ gcc --version
gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

$ openssl version
OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
```

You can compile the code with the command below.

```shell
$ make
```

If you run the binary, you will see the available commands.

```shell
$ ./asym.out 
too few arguments
keygen           : rsa generate key pair
encrypt          : rsa encrypt using public key
decrypt          : rsa decrypt using private key
ec-keygen        : ec generate key pair
ec-derive        : ec generate shared secret
ec-verify        : ec verify shared secret
sig              : signature sign and verification
cert-gen         : rsa generate certificate
cert-verify      : rsa verify certificate
tls              : tls communication
```










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


