# 

```shell
# load

xdp-loader load -m skb -s $PROG $IF "kernel/$PROG.o"

# unload

xdp-loader unload $IF -a
```