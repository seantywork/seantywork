
LINKS := -Loqs-provider/_build/lib -Wl,-rpath=oqs-provider/_build/lib 

all:
	gcc -c -o qs_common.o qs_common.c 

	gcc -c -o qs_tls.o qs_tls.c 

	gcc $(LINKS) -o qs.out qs.c qs_common.o qs_tls.o -l:oqsprovider.so -lssl -lcrypto 

clean:

	rm -rf *.o *.out