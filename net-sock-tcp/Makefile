CC      := gcc
CFLAGS  := -Wall -std=c99 -g
LIBS    := 

SERVER  := server.out 
CLIENT := client.out


all: $(SERVER) $(CLIENT)


$(SERVER):

	$(CC) $(CFLAGS) -o $(SERVER) server.c $(LIBS)


$(CLIENT):

	$(CC) $(CFLAGS) -o $(CLIENT) client.c $(LIBS)


clean:
	rm -f  *.o  *.out