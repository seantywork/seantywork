# socialize

I socialize on terminal

## develop

```shell

# build

make deps

make dev

```

```shell

# generate certs

./hack/tls.sh


```


```shell
# run engine

./engine.out
```

```shell
# run client

./cli.out "addr:port" number | cert location

# ex) ./cli.out "127.0.0.1:3001" tls/sub1.crt.pem

```


```shell
# it is also possible to login as admin specified in config.json
# at endpoint ${addr}:3000

# using command below

# gencert
#   : generates client cert
#   - data: client id


```