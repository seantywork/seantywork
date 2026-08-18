FLAGS := -g -Wall -O2
LIBS := -L/usr/local/lib -Wl,-rpath=/usr/local/lib -L/usr/lib64 -Wl,-rpath=/usr/lib64

all: nfqu.out xdpprog.o

nfqu.out:
	gcc $(FLAGS) $(LIBS) -o nfqu.out nfq_user.c -lbpf -lxdp -lpthread -lnetfilter_queue

xdpprog.o:
	clang -O2 -g -Wall -c -target bpf -o xdpprog.o xdpprog.c
clean:
	rm -rf *.o *.out