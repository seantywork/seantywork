CC      := gcc
CFLAGS  := -Wall -g
LIBS    := 

SERVER_P := server_p.out
NONBLOCK := nonblock.o
CLIENT := client.out


all: $(SERVER_P) $(CLIENT)


$(SERVER_P):

	$(CC) $(CFLAGS) -c -I. -o $(NONBLOCK) nonblock.c $(LIBS)


	$(CC) $(CFLAGS) -I. -o $(SERVER_P) server_p.c $(NONBLOCK) $(LIBS)

$(CLIENT):

	$(CC) $(CFLAGS) -I. -o $(CLIENT) client_p.c $(LIBS)


clean:
	rm -f  *.o  *.out 