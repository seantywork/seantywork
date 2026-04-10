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
|   public      |-------A's hint--------->|  private       |
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
As you can see above, calculated hint length is 1088, and the secret length is 32, which can be use for \
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
Using the hint and the private key, the decapsulation step checks if newly \
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

# misc

```shell
# cert 
openssl req -x509 -new -newkey mldsa65 -keyout ca.key.pem -out ca.crt.pem -nodes -subj "/CN=test CA" -days 365

openssl genpkey -algorithm mldsa65 -out srv.key.pem

openssl req -new -newkey mldsa65 -keyout srv.key.pem -out srv.csr -nodes -subj "/CN=test server" 

openssl x509 -req -in srv.csr -out srv.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365


```