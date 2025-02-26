LINKS := -Lliboqs/build/lib -Loqs-provider/_build/lib -Wl,-rpath=oqs-provider/_build/lib 

all:
	gcc -c -o qs_common.o qs_common.c 

	gcc $(LINKS) -o qs.out qs.c qs_common.o -loqs -loqs-internal -l:oqsprovider.so -lssl -lcrypto

clean:

	rm -rf *.o *.out