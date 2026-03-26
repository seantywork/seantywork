
INCL := -Iopenssl-qs/include -Iliboqs/build/include
LOC := $(INCL) -Lopenssl-qs -Wl,-rpath=openssl-qs -Lliboqs/build/lib -Wl,-rpath=liboqs/build/lib

all:
	gcc -g -O2 $(INCL) -c -o qs_common.o qs_common.c 
	gcc -g -O2 $(INCL) -c -o qs.o qs.c 
	gcc -g -O2 $(INCL) -c -o qs_tls.o qs_tls.c 

	gcc -g -O2 $(LOC) -o asym_qs.out main.c qs_common.o qs.o qs_tls.o -lpthread -loqs -lssl -lcrypto

clean:

	rm -rf *.o *.out