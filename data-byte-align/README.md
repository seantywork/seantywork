# byte-align

Byte-alignment means, in C program, that there could be a meaningful gains for the programmers \
who give a good care when defining a struct as they write codes.






There is a thing called [cpu cache](https://en.wikipedia.org/wiki/CPU_cache). \
It doesn't matter for many programmers for the most time until it **DOES** matter eventually.


```shell
$ getconf LEVEL1_DCACHE_LINESIZE
64

```