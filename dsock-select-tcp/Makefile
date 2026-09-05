CC      := gcc
CFLAGS  := -Wall  -g
LIBS    := 

SERVER_S := server_s.out
NONBLOCK := nonblock.o
CLIENT := client.out


all: $(SERVER_S) $(CLIENT)


$(SERVER_S):

	$(CC) $(CFLAGS) -c -I. -o $(NONBLOCK) nonblock.c $(LIBS)

	$(CC) $(CFLAGS) -I. -o $(SERVER_S) server_s.c $(NONBLOCK) $(LIBS)

$(CLIENT):

	$(CC) $(CFLAGS) -o $(CLIENT) client_s.c $(LIBS)


clean:
	rm -f  *.o  *.out