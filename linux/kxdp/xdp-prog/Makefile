all:

	clang -O2 -g -Wall -c -target bpf -o xdp_pass.o xdp_pass.c

	clang -O2 -g -Wall -c -target bpf -o xdp_drop.o xdp_drop.c

clean:
	rm -rf *.o