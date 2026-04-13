# crypt-asym-quantumsafe

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-crypt-asym-quantumsafe)

Here, I'm going to demonstrate how to use OpenSSL version 3.5+ to \
incorporate basic quantum safe functionalities into key generation, \
key exchange, digital signature, certificate generation, and TLS \
communication process.

To avoid the installation of OpenSSL version 3.5+ affecting the whole \
system, I'm going to keep the shared objects and libraries within this \
folder. Use `setup_openssl3.sh` to download and \
compile dependencies of this write-up.

```shell
$ ./setup_openssl3.sh
```

I have to choose what algorithm to use to demontrate postquantum \
cryptography. There are two notable and (in my opinion) widely adoptable \
algorithms for digital signature and key exchange, `mldsa65`, and `mlkem768`. \
I'm going to stick to those two for the whole tutorial.


If you've completed the installation, you will be able to compile the \
program as shown below.

```shell
$ make
```

Entering command without any argument reveals what kinds of operation \
you can execute using the program.

```shell
$ ./asym_qs.out 
invalid argument
keygen        : pq key generation 
encap         : pq key encap
decap         : pq key decap
sig           : pq signature 
cert-gen      : pq certificate generation 
cert-verify   : pq certificate verification 
tls           : pq tls 

```

Every entry is using OpenSSL 3.5.* for postquantum cryptography.

Let's get to the key generation!


```shell
# generate keys
$ ./asym_qs.out keygen
sig: mldsa65, kem: mlkem768
  keygen test succeeded

# checkout

$ ls certs/
mldsa65.key.pem  mldsa65_ca.key.pem  mldsa65_cli.key.pem  mlkem768.key.pem  mlkem768_ca.key.pem  mlkem768_cli.key.pem
mldsa65.pub.pem  mldsa65_ca.pub.pem  mldsa65_cli.pub.pem  mlkem768.pub.pem  mlkem768_ca.pub.pem  mlkem768_cli.pub.pem

```
For the tutorial, I've created keypair for `client`, `server`, and `CA`, for both of\
aformentioned algorithms, which leave us with a total of 12 files in the \
`certs` directory.

Now, let's see if we can use `mlkem768_ca` keypair to exchange \
shared key (for actual data encryption) between two different \
processes.

```shell
A                                         B
+---------------+                         +----------------+
|   B's         |                         |  B's           |
|   public      |-----A's wrappedkey----->|  private       |
|   key         |                         |  key           |
+---------------+                         +----------------+
      |                                           |
      | (encapsulation)                           | (decapsulation)
      |                                           |
      +----> calculated           calculated <----+
             shared key           share key
             on A's side          on B's side

- calculated shared key then used for secure communication
```

Let's run encapsulation step.

```shell
sig: mldsa65, kem: mlkem768
enclen: 1088, seclen: 32
0: D2 1: 3B 2: 6E 3: B5 4: 0F 5: 3E 6: 13 7: 92 8: 57 9: 3A 10: DB 11: F3 12: ED 13: F6 14: 0C 15: 0A 16: 5C 17: 01 18: 1A 19: 89 20: 4C 21: F0 22: 6D 23: BB 24: 6F 25: 75 26: 2F 27: 78 28: 10 29: E4 30: 66 31: BF 32: EF 
...
[CUT]
...
1072: BC 1073: 8E 1074: 3C 1075: 12 1076: C8 1077: B1 1078: 4D 1079: 49 1080: 15 1081: 74 1082: E3 1083: EA 1084: 1B 1085: E9 1086: 8A 1087: 18 
enclen: 1088
0: BC 1: 72 2: 01 3: 38 4: C6 5: 1E 6: CE 7: E0 8: 3C 9: 8E 10: C5 11: CD 12: A7 13: 7F 14: BE 15: C3 16: 8C 17: 6E 18: 22 19: BD 20: AE 21: AF 22: A0 23: 3D 24: 00 25: E8 26: 39 27: CC 28: D7 29: 80 30: D3 31: 9A 
seclen: 32
  encap test succeeded
```
As you can see above, calculated wrappedkey length is 1088, and the secret length is 32, which can be use for \
256bit symmetric cipher including AES256-GCM.

Now, let's see if we can decapsulate on the other side.

```shell
sig: mldsa65, kem: mlkem768
0: BC 1: 72 2: 01 3: 38 4: C6 5: 1E 6: CE 7: E0 8: 3C 9: 8E 10: C5 11: CD 12: A7 13: 7F 14: BE 15: C3 16: 8C 17: 6E 18: 22 19: BD 20: AE 21: AF 22: A0 23: 3D 24: 00 25: E8 26: 39 27: CC 28: D7 29: 80 30: D3 31: 9A 
0: D2 1: 3B 2: 6E 3: B5 4: 0F 5: 3E 6: 13 7: 92 8: 57 9: 3A 10: DB 11: F3 12: ED 13: F6 14: 0C 15: 0A 16: 5C 
...
[CUT]
...
1074: 3C 1075: 12 1076: C8 1077: B1 1078: 4D 1079: 49 1080: 15 1081: 74 1082: E3 1083: EA 1084: 1B 1085: E9 1086: 8A 1087: 18 
seclen: 32
  decap test succeeded
```
Using the wrappedkey and the private key, the decapsulation step checks if newly \
calculated secret key matches the other one calculated in the encapsulation \
step

```c
    // sec_msg is secret calculated in decapsulation step
    // peer_sec_bin is the secret calculated in encapsulation step
    if(memcmp(sec_msg, peer_sec_bin, sec_len) != 0){
        printf("memcmp failed\n");
        goto out;
    }
```

Now, it's time to check out how signature verification works. Though OpenSSL apis \
are slightly different, the overall flow of signing and verifying is the same as \
that one in case of RSA and eliptic curve.

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

Let's run it.

```shell
$ ./asym_qs.out sig
sig: mldsa65, kem: mlkem768
0: 2c 1: f2 2: 4d 3: ba 4: 5f 5: b0 6: a3 7: 0e 8: 26 9: e8 10: 3b 11: 2a 12: c5 13: b9 14: e2 15: 9e 16: 1b 17: 16 18: 1e 19: 5c 20: 1f 21: a7 22: 42 23: 5e 24: 73 25: 04 26: 33 27: 62 28: 93 29: 8b 30: 98 31: 24 
signed: siglen: 3309, hashlen: 32
result: 1
  signature test succeeded

```


Fun part to remember when generating postquantum certificates is that we should not \
supply message digest algorithm (at least when using `mlds65a`).

```shell

$ ./asym_qs.out cert-gen
sig: mldsa65, kem: mlkem768
cert create test succeeded
$ ls ./certs/ | grep crt
mldsa65.crt.pem
mldsa65_ca.crt.pem
mldsa65_cli.crt.pem
```

If you try to read the certificates using OpenSSL version below 3.5+, you will see \
something like below. Unable to decode the public key bytes and signature algorithm.

```shell
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: 2.16.840.1.101.3.4.3.18
        Issuer: C = CH, O = test.org, CN = localhost_ca
        Validity
            Not Before: Apr 10 04:58:23 2026 GMT
            Not After : Apr 10 04:58:23 2027 GMT
        Subject: C = CH, O = test.org, CN = localhost_ca
        Subject Public Key Info:
            Public Key Algorithm: 2.16.840.1.101.3.4.3.18
            Unable to load Public Key
40D7E635017E0000:error:03000072:digital envelope routines:X509_PUBKEY_get0:decode error:../crypto/x509/x_pubkey.c:458:
40D7E635017E0000:error:03000072:digital envelope routines:X509_PUBKEY_get0:decode error:../crypto/x509/x_pubkey.c:458:
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: 2.16.840.1.101.3.4.3.18
    Signature Value:
        d1:fa:2f:fe:e3:f5:e3:50:11:e9:aa:53:8b:ea:1d:99:78:d5:
        f6:c8:9b:07:67:ae:91:ee:09:68:87:c3:c1:c9:cc:46:69:4d:
        64:74:e7:ff:06:0b:a8:0d:9f:dd:24:d1:a3:3c:3d:a2:a3:05:
        e0:5d:57:2d:cc:49:81:b9:fa:3f:96:9c:cc:9f:f1:e8:5e:55:
```

It's time to check out if those certificates are correctly signed.

```shell
$ ./asym_qs.out cert-verify
sig: mldsa65, kem: mlkem768
result: 1
cert verify test succeeded
```

Finally, we get to the part where we let client and server communicate over \
secure channel established by mutal TLS.

```shell
$ ./asym_qs.out tls
sig: mldsa65, kem: mlkem768
client load ca: certs/mldsa65_ca.crt.pem
client file done: certs/mldsa65_cli.crt.pem
server load ca: certs/mldsa65_ca.crt.pem
server file done: certs/mldsa65.crt.pem
server thread created
server accept...
server accepted
  Issuer (cn): localhost_ca
  Subject (cn): localhost_ca
verify_callback (depth=1)(preverify=1)
  Issuer (cn): localhost_ca
  Subject (cn): localhost
verify_callback (depth=0)(preverify=1)
client ssl connected
client ssl verified
  Issuer (cn): localhost_ca
  Subject (cn): localhost_ca
verify_callback (depth=1)(preverify=1)
  Issuer (cn): localhost_ca
  Subject (cn): localhost_c
verify_callback (depth=0)(preverify=1)
server ssl accepted
success: server hello
tls net test succeeded

```

However, to really thoroughly see if I've done it correctly, I've decided to \
install OpenSSL 3.5+ system-wide and test the TLS communication using \
`openssl s_server` and `openssl s_client`.

Here's how to install it system-wide.

```shell

$ cd openssl-qs
$ sudo make install
$ sudo ldconfig /usr/local/lib64/
$ openssl version
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
```
Now, if I check the certificate, the public key section is correctly displayed.

```shell
$ openssl x509 -in certs/mldsa65_ca.crt.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: ML-DSA-65
        Issuer: C=CH, O=test.org, CN=localhost_ca
        Validity
            Not Before: Apr 13 07:27:43 2026 GMT
            Not After : Apr 13 07:27:43 2027 GMT
        Subject: C=CH, O=test.org, CN=localhost_ca
        Subject Public Key Info:
            Public Key Algorithm: ML-DSA-65
                ML-DSA-65 Public-Key:
                pub:
                    e3:46:88:1f:dd:4f:37:88:a7:2c:3a:a0:0e:30:86:
...
[CUT]
...
                    df:9b:6f:70:ad:2f:9d:a2:31:a8:0d:66:09:bf:67:
                    7a:2f
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ML-DSA-65
    Signature Value:
        67:54:c2:c9:3e:18:26:d7:a3:1b:b1:a4:9a:df:e5:b7:83:e2:
        0e:8e:1b:1d:5e:17:45:a9:6b:70:ac:b4:80:83:8f:08:b4:5d:
...
[CUT]
```

Run the server using programmatically generated certificates and keys...

```shell
# server
openssl s_server -key certs/mldsa65.key.pem -cert certs/mldsa65.crt.pem -CAfile certs/mldsa65_ca.crt.pem -port 9999

```

And connect from the client that is also using the programmatically generated certificates.\
You will see in the below, that the connection is successful, and TLS handshake using \
`mldsa65`, which is obviously a digital signature algorithm(thus not very obvious which\
key exchange mechanism it is using), is being done using a hybrid algorithm \
called `X25519MLKEM768`. \
More on this algorithm [here](https://www.netmeister.org/blog/tls-hybrid-kex.html). \
It seems using `mldsa65` implies(by default maybe?) `mlkem768` key generation and \
encap/decap process we've just seen above, along with `x25519` key derivation mechanism \
to have a final shared key.


```shell
# client
$ openssl s_client -connect localhost:9999 -key certs/mldsa65_cli.key.pem -cert certs/mldsa65_cli.crt.pem -CAfile certs/mldsa65_ca.crt.pem 
Connecting to 127.0.0.1
CONNECTED(00000003)
Can't use SSL_get_servername
depth=1 C=CH, O=test.org, CN=localhost_ca
verify return:1
depth=0 C=CH, O=test.org, CN=localhost
verify return:1
---
Certificate chain
 0 s:C=CH, O=test.org, CN=localhost
   i:C=CH, O=test.org, CN=localhost_ca
   a:PKEY: ML-DSA-65, 15616 (bit); sigalg: ML-DSA-65
   v:NotBefore: Apr 13 07:27:43 2026 GMT; NotAfter: Apr 13 07:27:43 2027 GMT
 1 s:C=CH, O=test.org, CN=localhost_ca
   i:C=CH, O=test.org, CN=localhost_ca
   a:PKEY: ML-DSA-65, 15616 (bit); sigalg: ML-DSA-65
   v:NotBefore: Apr 13 07:27:43 2026 GMT; NotAfter: Apr 13 07:27:43 2027 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIVXTCCCFqgAwIBAgIBATALBglghkgBZQMEAxIwNzELMAkGA1UEBhMCQ0gxETAP
...
[CUT]
...
J1F+hpveAgYINDZMCg4zQ0pVY2yAhIWVsdTZ6gAAAAAAAAAAAAAAAAAAAAIKEhge
KA==
-----END CERTIFICATE-----
subject=C=CH, O=test.org, CN=localhost
issuer=C=CH, O=test.org, CN=localhost_ca
---
No client certificate CA names sent
Peer signature type: mldsa65
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 15672 bytes and written 1604 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 15616 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
...
[CUT]
...
    00c0 - 93 d7 70 9e 02 fa de 0b-95 5c 6b ec fc 88 55 29   ..p......\k...U)

    Start Time: 1776065440
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
...
[CUT]
...
    Start Time: 1776065440
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK

```
Also, you can find some `openssl` commands to use for generating postquantum keys and \
certificates in the below section.

Thanks!



# misc

```shell
# cert 
openssl req -x509 -new -newkey mldsa65 -keyout ca.key.pem -out ca.crt.pem -nodes -subj "/CN=test CA" -days 365

openssl genpkey -algorithm mldsa65 -out srv.key.pem

openssl req -new -newkey mldsa65 -keyout srv.key.pem -out srv.csr -nodes -subj "/CN=test server" 

openssl x509 -req -in srv.csr -out srv.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365


```