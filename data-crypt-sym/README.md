# crypt-sym

- [code](https://github.com/seantywork/seantywork/tree/main/linux/data-crypt-sym)

Here, I'm trying to demonstrate how to use OpenSSL api to perform \
GCM256 and CBC256 cipher.

Unlike asymmetric cipher that involves both private key and \
public key, symmetric cipher (as its name suggests) only needs \
one same key on both sides to perform encryption and decryption. \
And even nicer fact is that it is inherently immune to quantum \
computer and its algorithm so that we can rely on a good old method \
of GCM256 (or CBC256). Due to this fact, even if one is going to \
have to update his OpenSSL to incorporate quantum safe algorithm to \
secure TLS communication after the q day, the actual encryption/decryption\
of the packet after key exchange remains under the reign of these symmetric \
cipher technologies.

Let's compile the program.

```shell
$ make
```

You'll have a binary named `sym.out` \
The following command shows what options you have with this \
program.

```shell
$ ./sym.out 
too few arguments
keygen  : generate key for encryption/decryption
enc-gcm : gcm encryption
dec-gcm : gcm decryption
enc-cbc : cbc encryption
dec-cbc : cbc decryption

```

As we're going to deal with the key size `256 bits` only in this\
tutorial, the generated key from the `keygen` command will be \
32-byte long.

```shell
$ ./sym.out keygen
0: 0E 1: 01 2: A7 3: 12 4: 30 5: 41 6: 03 7: 0F 8: AC 9: 57 10: 27 11: D3 12: 4B 13: 1B 14: 73 15: FE 16: BD 17: 58 18: C2 19: 1F 20: 95 21: 19 22: 82 23: 61 24: 82 25: 60 26: 84 27: B3 28: BD 29: 2C 30: 04 31: 0A 
0: 1F 1: 74 2: 17 3: BD 4: 61 5: FE 6: 9D 7: 19 8: F2 9: 92 10: 58 11: 48 
0: 9F 1: BB 2: 4E 3: C0 4: 14 5: F3 6: 23 7: CA 8: 58 9: 91 10: 01 11: 15 12: 66 13: 9B 14: 3A 15: 1E 
0: 2A 1: 98 2: 93 3: D1 4: 02 5: 98 6: E8 7: 4A 8: CF 9: 4F 10: 51 11: 06 12: 01 13: 76 14: 4D 15: 46 16: FF 17: 66 18: A7 19: 25 20: 95 21: 73 22: 84 23: 46 24: 67 25: 19 26: A1 27: 55 28: 9D 29: E2 30: FB 31: 6F 
success: keygen

$ ls | grep .data
auth_key.data
cbc_iv.data
iv.data
key.data
```
Here are what they are in the above `ls | grep` command result.
- auth_key: this is used for CBC256 HMAC message authentication
- cbc_iv: initiation vector used for CBC256 cipher, which is 16-byte long
- iv: initiation vector(nonce) used for GCM256 cipher, which is (unlink CBC) 12-byte long
- key: 23-byte long key used for both GCM256, and CBC256 cipher.

Now, with these materials, I'm going to perform `GCM256` encryption!

```shell
$ ./sym.out enc-gcm
0:  E 1:  1 2: A7 3: 12 4: 30 5: 41 6:  3 7:  F 8: AC 9: 57 10: 27 11: D3 12: 4B 13: 1B 14: 73 15: FE 16: BD 17: 58 18: C2 19: 1F 20: 95 21: 19 22: 82 23: 61 24: 82 25: 60 26: 84 27: B3 28: BD 29: 2C 30:  4 31:  A 
0: 1F 1: 74 2: 17 3: BD 4: 61 5: FE 6: 9D 7: 19 8: F2 9: 92 10: 58 11: 48 
outlen: 9
encrypt rv: 1
0: 05 1: 69 2: 27 3: 2F 4: 11 5: 49 6: 00 7: 31 8: FA 
0: 93 1: 90 2: 98 3: 3F 4: 07 5: 4C 6: 2F 7: D5 8: 51 9: CC 10: 58 11: 85 12: 22 13: 45 14: B0 15: D3 
success: enc-gcm
```
Below is a diagram that describes what's going on. \
`message` and `additional data` are hard-coded. \
`additional data` is not an absolute necessity, however, it is \
often used in protocols such as IPSec. 

```shell
+-----------+
| message   |
|"cryptoinc"|---------------------------+
+-----------+                           |
+-----------+                           |
|additional |                           |
|data       |-----------------------+   |
|"vvvvvvvv" |                       |   |
+-----------+                       |   |
+-----------+                       |   |
|32-byte key|-----------------+     |   |
+-----------+                 |     |   |
+-----------+                 |     |   |
|12-byte    |                 |     |   |
|nonce      |----------+      |     |   |
+-----------+          |      |     |   |
                       V      V     V   V
+-----------------------------------------------+
|                                               |
|                     GCM256 encryption         |
|                                               |
+-----------------------------------------------+
                        |     |
+-----------+           |     |
|encrypted  |           |     |
|message    |<----------+     |
+-----------+                 |
+-----------+                 |
|16-byte    |                 |
|tag        |<----------------+
+-----------+
```

As seen above diagram, we can check resulted data `enc.bin` and `tag.data` \
in the directory.

```shell
$ ls | grep -E 'enc|tag'
enc.bin
tag.data
```

Now, it's time to decrypt the message.

```shell
$ ./sym.out dec-gcm
0:  E 1:  1 2: A7 3: 12 4: 30 5: 41 6:  3 7:  F 8: AC 9: 57 10: 27 11: D3 12: 4B 13: 1B 14: 73 15: FE 16: BD 17: 58 18: C2 19: 1F 20: 95 21: 19 22: 82 23: 61 24: 82 25: 60 26: 84 27: B3 28: BD 29: 2C 30:  4 31:  A 
0: 1F 1: 74 2: 17 3: BD 4: 61 5: FE 6: 9D 7: 19 8: F2 9: 92 10: 58 11: 48 
0: 93 1: 90 2: 98 3: 3F 4:  7 5: 4C 6: 2F 7: D5 8: 51 9: CC 10: 58 11: 85 12: 22 13: 45 14: B0 15: D3 
0:  5 1: 69 2: 27 3: 2F 4: 11 5: 49 6:  0 7: 31 8: FA 
decrypt rv: 1
cryptoinc
success: dec-gcm
```
You can see the original message is recovered without error. \
Below is the diagram that describes the process.


```shell
+-----------+
|encrypted  |
|messsage   |---------------------------+
+-----------+                           |
+-----------+                           |
|additional |                           |
|data       |-----------------------+   |
|"vvvvvvvv" |                       |   |
+-----------+                       |   |
+-----------+                       |   |
|32-byte key|-----------------+     |   |
+-----------+                 |     |   |
+-----------+                 |     |   |
|12-byte    |                 |     |   |
|nonce      |----------+      |     |   |
+-----------+          |      |     |   |
+-----------+          |      |     |   |
|16-byte    |          |      |     |   |
|tag        |-----+    |      |     |   |
+-----------+     |    |      |     |   |
                  V    V      V     V   V
+-----------------------------------------------+
|                                               |
|                     GCM256 decryption         |
|                                               |
+-----------------------------------------------+
                        |     
+-----------+           |     
|decrypted  |           |     
|message    |<----------+     
+-----------+                 


```

Now, as I'm going to move on to CBC256 encryption.

```shell
$ ./sym.out enc-cbc
padlen: 0
0:  E 1:  1 2: A7 3: 12 4: 30 5: 41 6:  3 7:  F 8: AC 9: 57 10: 27 11: D3 12: 4B 13: 1B 14: 73 15: FE 16: BD 17: 58 18: C2 19: 1F 20: 95 21: 19 22: 82 23: 61 24: 82 25: 60 26: 84 27: B3 28: BD 29: 2C 30:  4 31:  A 
0: 9F 1: BB 2: 4E 3: C0 4: 14 5: F3 6: 23 7: CA 8: 58 9: 91 10:  1 11: 15 12: 66 13: 9B 14: 3A 15: 1E 
0: 2A 1: 98 2: 93 3: D1 4:  2 5: 98 6: E8 7: 4A 8: CF 9: 4F 10: 51 11:  6 12:  1 13: 76 14: 4D 15: 46 16: FF 17: 66 18: A7 19: 25 20: 95 21: 73 22: 84 23: 46 24: 67 25: 19 26: A1 27: 55 28: 9D 29: E2 30: FB 31: 6F 
hmac success
0: 7D 1: 2C 2: 48 3: A7 4: 1B 5: 18 6: F4 7: 41 8: 2A 9: 02 10: 69 11: E0 12: 5C 13: 98 14: 4E 15: 31 16: F1 17: F2 18: B4 19: 55 20: AC 21: 41 22: 48 23: CE 24: 11 25: 55 26: 59 27: 93 28: DB 29: EA 30: B7 31: 83 
encrypt rv: 1
0: 97 1: A0 2: FC 3: 8E 4: 65 5: EE 6: BC 7: 89 8: 1E 9: FC 10: 4B 11: 6F 12: 54 13: C3 14: 76 15: FC 
success: enc-cbc

```

It looks a bit more verbost than GCM256! It's not because this method is \
particularly more secure than GCM256. It's because CBC256 is an older cipher \
suite that involves a spec of manual message modification (due to the fact that \
it is a block cipher unlike GCM256, which is a stream cipher) and message \
authentication.

Here's the diagram.

```shell
+-----------+
| message   |
|"cryptoinc"|---------------------------+
|           |                           |
|           | (with padding if length   |
|           |  is not divisible by      |
|           |  AES block length)        |
+-----------+                           |
+-----------+                           |
|32-byte    |                           |
|HMAC       |-----------------------+   |
|auth key   |                       |   |
+-----------+                       |   |
+-----------+                       |   |
|32-byte key|-----------------+     |   |
+-----------+                 |     |   |
+-----------+                 |     |   |
|16-byte    |                 |     |   |
|iv         |----------+      |     |   |
+-----------+          |      |     |   |
                       V      V     V   V
+-----------------------------------------------+
|                                               |
|                     CBC256 encryption         |
|                     + HMAC auth message       |
|                       generation              |
+-----------------------------------------------+
                        |     |
+-----------+           |     |
|encrypted  |           |     |
|message    |<----------+     |
+-----------+                 |
+-----------+                 |
|32-byte    |                 |
|auth       |<----------------+
|message    |
|           | (can be truncated)
+-----------+
```

Now, let's perform the final act of decrypting CBC256 encrypted message.

```shell
$ ./sym.out dec-cbc
0:  E 1:  1 2: A7 3: 12 4: 30 5: 41 6:  3 7:  F 8: AC 9: 57 10: 27 11: D3 12: 4B 13: 1B 14: 73 15: FE 16: BD 17: 58 18: C2 19: 1F 20: 95 21: 19 22: 82 23: 61 24: 82 25: 60 26: 84 27: B3 28: BD 29: 2C 30:  4 31:  A 
0: 9F 1: BB 2: 4E 3: C0 4: 14 5: F3 6: 23 7: CA 8: 58 9: 91 10:  1 11: 15 12: 66 13: 9B 14: 3A 15: 1E 
0: 2A 1: 98 2: 93 3: D1 4:  2 5: 98 6: E8 7: 4A 8: CF 9: 4F 10: 51 11:  6 12:  1 13: 76 14: 4D 15: 46 16: FF 17: 66 18: A7 19: 25 20: 95 21: 73 22: 84 23: 46 24: 67 25: 19 26: A1 27: 55 28: 9D 29: E2 30: FB 31: 6F 
0: 7D 1: 2C 2: 48 3: A7 4: 1B 5: 18 6: F4 7: 41 8: 2A 9:  2 10: 69 11: E0 12: 5C 13: 98 14: 4E 15: 31 16: F1 17: F2 18: B4 19: 55 20: AC 21: 41 22: 48 23: CE 24: 11 25: 55 26: 59 27: 93 28: DB 29: EA 30: B7 31: 83 
0: 97 1: A0 2: FC 3: 8E 4: 65 5: EE 6: BC 7: 89 8: 1E 9: FC 10: 4B 11: 6F 12: 54 13: C3 14: 76 15: FC 
decrypt rv: 1
hmac success
authenticated
cryptoinc
success: dec-cbc
```

Usually, HMAC is done on encrypted payload + something additional, \
such as initication vector, but I'm performing this purely over \
my file system, I decided to take short cut and perform this on \
original message only :) 

Here's the description of CBC256 decryption process.


```shell

+-----------+
|encrypted  |
|messsage   |---------------------------+
+-----------+                           |
+-----------+                           |
|32-byte    |                           |
|HMAC       |-----------------------+   |
|auth key   |                       |   |
+-----------+                       |   |
+-----------+                       |   |
|32-byte key|-----------------+     |   |
+-----------+                 |     |   |
+-----------+                 |     |   |
|16-byte    |                 |     |   |
|iv         |----------+      |     |   |
+-----------+          |      |     |   |
+-----------+          |      |     |   |
|32-byte    |          |      |     |   |
|HMAC       |-----+    |      |     |   |
|messsage   |     |    |      |     |   |
+-----------+     |    |      |     |   |
                  V    V      V     V   V
+-----------------------------------------------+
|                                               |
|                     CBC256 decryption         |
|                     + HMAC message            |
|                       verification            |
+-----------------------------------------------+
                        |     
+-----------+           |     
|decrypted  |           |     
|message    |<----------+     
+-----------+        

```

Thanks!