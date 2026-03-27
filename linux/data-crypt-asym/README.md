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


For this command and the rest, it doesn't matter which kind of key to use. I'm \
going to go with EC.

I'm going to use `ca_priv.pem` as the private key and `ca_pub.pem` as \
its public key.

Let's check out.

```shell
$ ./asym.out sig
0: 2c 1: f2 2: 4d 3: ba 4: 5f 5: b0 6: a3 7: 0e 8: 26 9: e8 10: 3b 11: 2a 12: c5 13: b9 14: e2 15: 9e 16: 1b 17: 16 18: 1e 19: 5c 20: 1f 21: a7 22: 42 23: 5e 24: 73 25: 04 26: 33 27: 62 28: 93 29: 8b 30: 98 31: 24 
signed: siglen: 71, hashlen: 32
result: 1
sig success
```

Now, with all these tests passed, it's time to do find out something that \
is more family to all of us.

Let's create certificates!

For this tutorial, I'm going to create a total of three certificates, which are \
`ca.crt.pem`, `srv.crt.pem`, and `cli.crt.pem`. \
The latter two are signed by the `ca` and all of them will \
be used to demonstrate the working of mutual TLS communication \
of the `srv` server and `cli` client.

This is the command to generate certs based on the keys

```shell
$ ./asym.out cert-gen
cert-gen success

```

You can check the content of these certificates using the comman below.

```shell
$ openssl x509 -in srv.crt.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5f:4e:18:63:11:42:9e:8e:08:f3:d6:ff:65:6d:7e:72:33:86:0c:67
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = localhost_ca
        Validity
            Not Before: Mar 27 05:56:31 2026 GMT
            Not After : Mar 27 05:56:31 2027 GMT
        Subject: CN = localhost
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ac:31:08:1a:9b:29:90:3e:9e:59:ef:7d:a6:43:
                    71:9a:e5:e0:ac:92:84:90:04:73:53:6b:83:e6:7d:
                    52:9b:04:60:bd:27:78:53:b6:26:3a:de:be:60:f8:
                    07:3e:36:1a:b9:df:68:11:f5:95:e3:fc:c8:d9:27:
                    b7:ea:bf:06:a3
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                AE:06:EE:43:25:EB:2C:4F:CD:EB:BA:56:81:0B:C6:84:93:6C:51:B4
            X509v3 Authority Key Identifier: 
                74:AD:30:12:B8:D9:FA:0B:B2:49:90:BC:85:D2:87:96:25:6B:28:6A
            X509v3 Subject Alternative Name: 
                DNS:localhost
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:40:2f:70:b9:d9:1c:bf:81:34:23:6d:7c:3d:d5:
        8c:08:5e:33:74:77:84:79:4a:66:61:e6:16:cd:0e:24:5c:67:
        02:21:00:a0:45:7a:5e:26:84:35:0d:22:d4:72:d0:a3:3e:2b:
        be:d7:5e:49:24:48:31:cd:32:e9:c0:c7:6d:bc:2f:92:59

```

Let's check if server certificate is verifiable using ca certicate.

```shell
$ ./asym.out cert-verify
cert-verify success
```
By changing the first argument to the below function, you can \
see for yourself if client certificate is also verifiable by ca \
certificate.

```c
// main.c
        result = cert_verify(cert_path_s, cert_path);
        if(result != 1){
            fprintf(stderr,"%s failed: %d\n",argv[1], result);
            return result;
        } else {
            fprintf(stdout, "%s success\n", argv[1]);
        }  

```

Finally, this is the part where I'll test out mutual TLS between \
the client and the server works using these certificates.

Here is the command to do so.

```shell

$ ./asym.out tls
client load ca: ./ca.crt.pem
client file done: ./cli.crt.pem
server load ca: ./ca.crt.pem
server file done: ./srv.crt.pem
server thread created
server accept...
server accepted
  issuer cn: : localhost_ca
  subject cn: : localhost_ca
verify_callback (depth=1)(preverify=1)
  issuer cn: : localhost_ca
  subject cn: : localhost
verify_callback (depth=0)(preverify=1)
client ssl connected
client ssl verified
  issuer cn: : localhost_ca
  subject cn: : localhost_ca
verify_callback (depth=1)(preverify=1)
  issuer cn: : localhost_ca
  subject cn: : client
verify_callback (depth=0)(preverify=1)
server ssl accepted
success: server hello
tls success
```
As you can see above, client side first checks if the certificate is \
correct, which is observable because we see `  subject cn: : localhost` \
line first where comman name `localhost` is the server certificate.
Then, followed immediately, server side also checks the certificate \
sent by client, which is observable as we see `  subject cn: : client`.

The Test terminates as the server successfully receives the string \
`hello` from the client.

Thank you for reading this, goodday!

Below are some miscellaneous OpenSSL commands regarding key generation\
, certificate generation.



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


