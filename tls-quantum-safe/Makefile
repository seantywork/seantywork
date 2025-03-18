
INCLUDES := -Iinclude

LIBS := -lssl -lcrypto 

all:
	gcc -g -c $(INCLUDES) -o common.o common.c 

	gcc -g $(INCLUDES) -o client.out client/main.c common.o $(LIBS)

	gcc -g $(INCLUDES) -o server.out server/main.c common.o $(LIBS)

clean:

	rm -rf *.o *.out