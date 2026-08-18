CFLAGS  := -Wall -std=c99 -g
LIBS    := -lcrypto -lssl -lpthread


SERVER  := server/server.out 
CLIENT := client/client.out


all: $(SERVER) $(CLIENT)


$(SERVER):

	$(CC) $(CFLAGS) -o $(SERVER) server/main.c $(LIBS)

$(CLIENT):

	$(CC) $(CFLAGS) -o $(CLIENT) client/main.c $(LIBS)


clean:	
	rm -rf server/*.o server/*.out client/*.o client/*.out 