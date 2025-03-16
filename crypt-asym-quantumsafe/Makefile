
LINKS := -Loqs-provider/_build/lib -Wl,-rpath=oqs-provider/_build/lib 

all:
	gcc -g -c -o qs_common.o qs_common.c 

	gcc -g -c -o qs_tls.o qs_tls.c 

	gcc -g $(LINKS) -o qs.out qs.c qs_common.o qs_tls.o -l:oqsprovider.so -lssl -lcrypto -lpthread

clean:

	rm -rf *.o *.out