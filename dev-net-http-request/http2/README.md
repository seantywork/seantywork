#
```shell
curl --http2 -v \
  --cacert tls/ca.crt \
  --cert tls/client.crt \
  --key tls/client.key \
  https://server.test:8888/index.html


curl --http2-prior-knowledge -v \
  --cacert tls/ca.crt \
  --cert tls/client.crt \
  --key tls/client.key \
  https://server.test:8888/index.html


``


```shell
./req.out https://server.test:8888/index.html ../../dev-net-http-server/http2/tls/ca.crt ../../dev-net-http-server/http2/tls/client.crt ../../dev-net-http-server/http2/tls/client.key
```