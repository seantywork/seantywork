
CFLAGS      := -std=c99 -Wall -g 

INCLUDES    := -I.

LIBS        := -lssl -lcrypto -lm -ldl

all:

	gcc $(INCLUDES) -o server/server.out server/main.c $(LIBS)

	gcc $(INCLUDES) -o client/client.out client/main.c $(LIBS)

clean:

	rm -r *.out