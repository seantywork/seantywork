all:

	gcc -g -c -o af_rxtx.o af_rxtx.c

	gcc -g -L/usr/local/lib -Wl,-rpath=/usr/local/lib -L/usr/lib64 -Wl,-rpath=/usr/lib64  -o run.out main.c af_rxtx.o -lbpf -lxdp


clean:

	rm -rf *.out *.o