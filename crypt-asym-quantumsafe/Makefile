all:

	gcc -c -o qs_common.o qs_common.c 

	gcc -Loqs-provider/_build/lib -Wl,-rpath=oqs-provider/_build/lib -o qs.out qs.c qs_common.o -loqs -l:oqsprovider.so -lssl -lcrypto

clean:

	rm -rf *.o *.out