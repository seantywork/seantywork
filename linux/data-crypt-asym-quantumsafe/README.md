# crypt-asym-quantumsafe

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-crypt-asym-quantumsafe)

Here, I'm going to demonstrate how to use OpenSSL version 3.5+ to \
incorporate basic quantum safe functionalities into key generation, \
key exchange, digital signature, certificate generation, and TLS \
communication process.

To avoid the installation of OpenSSL version 3.5+ affecting the whole \
system, I'm going to keep the shared objects and libraries within this \
folder. Use `setup_openssl3.sh` and `setup_liboqs.sh` to download and \
compile dependencies of this write-up.

```shell
$ ./setup_openssl3.sh
$ ./setup_liboqs.sh
```

While it's not necessary to install `liboqs` if I'm focusing 100% on \
OpenSSL, but I included it because I also wanted to share how to use \  
that library to generate keys, manage key encapsulation and \
digital signature.

Also, I have to choose what algorithm to use to demontrate postquantum \
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
oqs-kem       : pq key encap/decap using liboqs 
oqs-sig       : pq signature using liboqs 
cert-gen      : pq certificate generation 
cert-verify   : pq certificate verification 
tls           : pq tls 

```

Except of entry beginning with `oqs-*`, every entry is using OpenSSL 3.5.* \
for postquantum cryptography.

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

I'll defer `liboqs` demonstration until we get through the certificates and TLS \
communication part.

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

# misc

```shell
# cert 
openssl req -x509 -new -newkey mldsa65 -keyout ca.key.pem -out ca.crt.pem -nodes -subj "/CN=test CA" -days 365

openssl genpkey -algorithm mldsa65 -out srv.key.pem

openssl req -new -newkey mldsa65 -keyout srv.key.pem -out srv.csr -nodes -subj "/CN=test server" 

openssl x509 -req -in srv.csr -out srv.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365


```