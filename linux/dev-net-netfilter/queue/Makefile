FLAGS := -g -Wall -O2

all: nfqu.out xdpprog.o

nfqu.out:
	gcc $(FLAGS) -o nfqu.out nfq_user.c -lbpf -lxdp -lpthread -lnetfilter_queue

xdpprog.o:
	clang -O2 -g -Wall -c -target bpf -o xdpprog.o xdpprog.c
clean:
	rm -rf *.o *.out