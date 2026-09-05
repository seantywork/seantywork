FLAG := -g -Wall -O2
INC := -Iopenssl-qs/include #-Iliboqs/build/include
LIB := -Lopenssl-qs -Wl,-rpath=openssl-qs #-Lliboqs/build/lib -Wl,-rpath=liboqs/build/lib
LIB_NAMES := -lpthread -lssl -lcrypto #-loqs 

all: qs_common.o qs.o qs_tls.o
	gcc $(FLAG) $(INC) $(LIB) -o asym_qs.out main.c qs_common.o qs.o qs_tls.o $(LIB_NAMES)

qs_common.o:
	gcc $(FLAG) $(INC) $(LIB) -c -o qs_common.o qs_common.c 

qs.o:
	gcc $(FLAG) $(INC) $(LIB) -c -o qs.o qs.c 

qs_tls.o:
	gcc $(FLAG) $(INC) $(LIB) -c -o qs_tls.o qs_tls.c 


clean:

	rm -rf *.o *.out