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
OpenSSL, but I included it because I also wanted to share how to use \  that library to generate keys, manage key encapsulation and \
digital signature.

# misc

```shell
# cert 
openssl req -x509 -new -newkey mldsa65 -keyout ca.key.pem -out ca.crt.pem -nodes -subj "/CN=test CA" -days 365

openssl genpkey -algorithm mldsa65 -out srv.key.pem

openssl req -new -newkey mldsa65 -keyout srv.key.pem -out srv.csr -nodes -subj "/CN=test server" 

openssl x509 -req -in srv.csr -out srv.crt.pem -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -days 365


```