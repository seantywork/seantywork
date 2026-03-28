CC      := gcc
CFLAGS  := -Wall -g
LIBS    := -lpthread

SERVER_EP := server_ep.out
HANDLE := server_handle.o
CLIENT := client.out


all: $(SERVER_EP) $(CLIENT)


$(SERVER_EP):

	$(CC) $(CFLAGS) -c -o $(HANDLE) server_handle.c 

	$(CC) $(CFLAGS) -o $(SERVER_EP) server_ep.c $(HANDLE) $(NONBLOCK) $(LIBS)

$(CLIENT):

	$(CC) $(CFLAGS) -o $(CLIENT) client_p.c $(LIBS)


clean:
	rm -f  *.o  *.out 