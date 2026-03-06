CFLAGS  := -Wall -g
LIBS    := -lcrypto -lssl -lpthread


SERVER  := server/server.out 
TLS := server/server_tls.o
HANDLE := server/server_handle.o
NONBLOCK := server/nonblock.o
CLIENT := client/client.out


all: $(SERVER) $(CLIENT)


$(SERVER):

	$(CC) $(CFLAGS) -c -o $(NONBLOCK) server/nonblock.c 

	$(CC) $(CFLAGS) -c -o $(TLS) server/server_tls.c 

	$(CC) $(CFLAGS) -c -o $(HANDLE) server/server_handle.c 

	$(CC) $(CFLAGS) -o $(SERVER) server/main.c $(HANDLE) $(TLS) $(NONBLOCK) $(LIBS)

$(CLIENT):

	$(CC) $(CFLAGS) -o $(CLIENT) client/main.c $(LIBS)


clean:
	rm -f  server/*.o server/*.out client/*.o client/*.out 