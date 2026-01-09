all:

	gcc -g -L/usr/local/lib -Wl,-rpath=/usr/local/lib -L/usr/lib64 -Wl,-rpath=/usr/lib64  -o run.out main.c  -lbpf -lxdp


clean:

	rm -rf *.out *.o