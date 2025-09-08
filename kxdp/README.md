# 

```shell
# load

xdp-loader load -m native -s xdp_pass kxdp0 "xdp_pass.o"

xdp-loader load -m native -s xdp_pass kxdp1 "xdp_pass.o"

# unload

xdp-loader unload $IF -a
```