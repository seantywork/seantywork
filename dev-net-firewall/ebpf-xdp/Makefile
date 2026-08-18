all:

	gcc -g -L/usr/local/lib -Wl,-rpath=/usr/local/lib -L/usr/lib64 -Wl,-rpath=/usr/lib64  -o user.out user.c  -lbpf -lxdp

	make -C prog

clean:

	rm -rf *.out *.o