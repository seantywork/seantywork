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
Ones that begin with `ec-*` are operations using eliptic curve \
rather than RSA.

First, I'm going to go with RSA key generation and show you how to \
encrypt a piece of secret data using the public key, followed by decryption \
using the private key.

Let's create RSA key pairs(it's plural because I'm going to create \
multiple key pairs to be used as CA, server, and client going forward).

```shell
$ ./asym.out keygen
keygen success

$ ls | grep pem
c_priv.pem
c_pub.pem
ca_priv.pem
ca_pub.pem
s_priv.pem
s_pub.pem

$ cat ca_priv.pem 
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDdnUuJBECaWN3e
slvI6qLmh6GlFhl9t0bVIiTWeDIYonr9uKnd4wbxA1FCcKRe+RIccwcHAIXZoZR3
$ cat ca_pub.pem 
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3Z1LiQRAmljd3rJbyOqi
5oehpRYZfbdG1SIk1ngyGKJ6/bip3eMG8QNRQnCkXvkSHHMHBwCF2aGUd5FMpvDF

```

RSA-based key sharing is described in the diagram below.

```shell
generate                                    decrypt
shared key                                  shared key
      |                                           ^
      |                                           |
      V                                           |
+---------------+                         +----------------+
|   A's         |                         |  A's           |
|   public      |                         |  private       |
|   key         |                         |  key           |
+---------------+                         +----------------+
      |                                           |
      |                                           |
      |                                           |
      +------   encrypt shared key -------->  ----+
```


Now, let's encrypt a message `cryptoinc` using the public key named \
`ca_pub.pem`

```shell

$./asym.out encrypt
original message: cryptoinc
0: 0F 1: 92 2: 82 3: 19 4: 87 5: FA 6: 91 7: 3E 8: 27 9: 7B 10: 33 11: 08 12: 77 13: B5 14: 38 15: 95 16: F7 17: 80 18: E5 19: 42 20: D9 21: 42 22: 5D 23: 9A 24: BB 25: D0 26: 37 27: C0 28: 10 29: 9C 30: A8 31: 3F
[CUT]
501: 9B 502: F3 503: 9A 504: 2F 505: C6 506: AC 507: 75 508: B3 509: 61 510: 4A 511: 45 
enclen: 512
encrypt success

```
As you can see above, this command displays the resulting binary data \
of the public encryption operation, along with the total length of \
that data. 

The total length of the result of this operation is determined by \
the RSA key bits length, and in this case, it's 4096. Changing macro \
value below in file `asym.h` will also change the resulting data \ length, and crucially the max length of the original message.

```c
#define THIS_RSA_BITS 4096
```
You can also check out the result in file `enc_msg.bin`.

```shell
$ cat enc_msg.bin
0F92821987FA913E277B330877B53895F780E542D9425D9ABBD037C0109CA83FDDA6B1EFA4DADA51A2EB26AA46E1F43E410E3E81BBBD2ECFA9C3C81FEB8952FBA5C19002F4445C0B039AF79113FBA5BEA8CBF6AAC6476AC293834FF8D2D18F22437AB6
[CUT]
```

Now, let's decrypt this using the private key.

```shell
$ ./asym.out decrypt
0: 0F 1: 92 2: 82 3: 19 4: 87 5: FA 6: 91 7: 3E 8: 27 9: 7B 10: 33 11: 08 12: 77 13: B5 14: 38 15: 95 16: F7 17: 80 18: E5 19: 42 20: D9 21: 42 22: 5D 23: 9A 24: BB 25: D0 26: 37 27: C0 28: 10 29: 9C 30: A8 31: 3F
[CUT]
501: 9B 502: F3 503: 9A 504: 2F 505: C6 506: AC 507: 75 508: B3 509: 61 510: 4A 511: 45 
declen: 9
original message: cryptoinc
decrypt success

```
As you can see, the decryption is successfully done and the orinal \
message `cryptoinc` is retrieved.

In case of RSA, this function is mainly used to communicate a shared \
secret per session securely between two parties (namely client and \
server)

How about eliptic curve? Let's find out.

You can create EC key pairs using the command below.

```shell
$ ./asym.out ec-keygen
ec-keygen success

```

In case of EC, you cannot directly use RSA's encryption/decryption, but \
something equivalent is called "derivation".

If party A and party B want to securely communicate a shared secret, \
what they need is each other's public key, which is used along with \
each party's own private key to derive a share secret key separately. \
Here is a simple diagram.

```shell
- assuming same EC curve (in this case prime256v1)
+---------------+                         +----------------+
|   A's         |                         |  B's           |
|   private     |----A's public key------>|  private       |
|   key         |<---B's public key-------|  key           |
+---------------+                         +----------------+
      |                                           |
      |                                           |
      |                                           |
      +----> calculated           calculated <----+
             shared key           share key
             on A's side          on B's side

- calculated shared key then used for secure communication
```

With this example, I'm going to use `s_priv.pem` and `s_pub.pem` as A, \
and `ca_priv.pem` and `ca_pub.pem` as B.

Let's first derive the shared key on A's side.

```shell
$ ./asym.out ec-derive
0: BE 1: 49 2: 43 3: 42 4: E2 5: 4A 6: 42 7: 77 8: 02 9: DA 10: 08 11: 35 12: EE 13: 78 14: F4 15: 3B 16: F8 17: 63 18: 75 19: 97 20: 4B 21: C1 22: EF 23: 37 24: 4A 25: 99 26: C3 27: A5 28: 5B 29: F4 30: 15 31: 53 
skey len: 32
ec-derive success
```

As you can see, data with length of 32 (which is surely can be used for \
such algorithms as AES-256)

You can check the raw binary of this data as below.

```shell
$ cat shared_key.bin 
BE494342E24A427702DA0835EE78F43BF86375974BC1EF374A99C3A55BF41553
```

Now let's generate the data on B's side, and check if that data matches \
with the data generated on A's side.

```shell
$ ./asym.out ec-verify
skeylen: 32
0: BE 1: 49 2: 43 3: 42 4: E2 5: 4A 6: 42 7: 77 8: 02 9: DA 10: 08 11: 35 12: EE 13: 78 14: F4 15: 3B 16: F8 17: 63 18: 75 19: 97 20: 4B 21: C1 22: EF 23: 37 24: 4A 25: 99 26: C3 27: A5 28: 5B 29: F4 30: 15 31: 53 
ec-verify success

```
They're the same, as you can see from the hex display of both results.


Now, I'm going to test out the process of generating digital signature and \
verifying it. Generating a digital signature involves digesting the target \
content, then signing it with the private key. \
Verifying the digital signature involves digesting the target content(independently) \
then verifying the digital signature against the digest using the public key.

Below is the diagram describing the process.

```shell
message: hello
      |
      |
      V
SHA256 digest of it:
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
      |
      |
      V
sign the digest with:
+---------------+
|   A's         |
|   private key |
+---------------+
      |
      |
      V
verify the signature with:
+---------------+
|   A's         |    &  independently calculated
|   public key  |       SHA256 digest
+---------------+       on the same message
```


For this one and the rest, it doesn't matter which kind of key to use. I'm \
going to go with EC.







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


