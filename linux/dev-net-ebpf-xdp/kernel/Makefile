all:
	clang -O2 -g -Wall -c -target bpf -o xdp_redirect_xsk.o xdp_redirect_xsk.c

	clang -O2 -g -Wall -c -target bpf -o xdp_redirect_dev.o xdp_redirect_dev.c

	clang -O2 -g -Wall -c -target bpf -o xdp_map_allow.o xdp_map_allow.c

	clang -O2 -g -Wall -c -target bpf -o xdp_pass.o xdp_pass.c

	clang -O2 -g -Wall -c -target bpf -o xdp_packet_block.o xdp_packet_block.c

