

all:
	gcc -g -c -o qs_common.o qs_common.c 

	gcc -g -c -o qs_tls.o qs_tls.c 

	gcc -g -o qs.out qs.c qs_common.o qs_tls.o -loqs -lssl -lcrypto -lpthread

clean:

	rm -rf *.o *.out