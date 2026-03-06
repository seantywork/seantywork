
LOC := -Iopenssl-qs/include -Iliboqs/build/include -Lopenssl-qs -Wl,-rpath=openssl-qs -Lliboqs/build/lib -Wl,-rpath=liboqs/build/lib

all:
	gcc -g -c -o qs_common.o qs_common.c 

	gcc -g -c -o qs_tls.o qs_tls.c 

	gcc -g $(LOC) -o qs.out qs.c qs_common.o qs_tls.o -lpthread -loqs -lssl -lcrypto

clean:

	rm -rf *.o *.out