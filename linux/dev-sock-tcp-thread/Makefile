CC      := gcc
CFLAGS  := -Wall  -g
LIBS    := -lpthread

SERVER_ST := server_st.out
WORKER := worker.o
SERVER_HANDLE := server_thandle.o
NONBLOCK := tnonblock.o
CLIENT := client.out


all: $(SERVER_ST) $(CLIENT)


$(SERVER_ST):

	$(CC) $(CFLAGS) -c -o $(NONBLOCK) tnonblock.c 

	$(CC) $(CFLAGS) -c -o $(SERVER_HANDLE) server_thandle.c 

	$(CC) $(CFLAGS) -c -o $(WORKER) worker.c 

	$(CC) $(CFLAGS) -o $(SERVER_ST) server_st.c $(WORKER) $(SERVER_HANDLE) $(NONBLOCK) $(LIBS)

$(CLIENT):

	$(CC) $(CFLAGS) -o $(CLIENT) client_p.c 


clean:
	rm -f  *.o  *.out 8*