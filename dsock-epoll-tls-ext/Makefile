GCC_FLAGS := -Wall -g

GCC_OBJ_FLAGS := -Wall -g -c

H2LIB := nghttp2-1.70.0

INCLUDES := -I./include -I$(H2LIB)/lib/includes -I$(H2LIB)/third-party/urlparse/

LIBS := -lpthread -lssl -lcrypto -lnghttp2 -lurlparse

LINKS := -L$(H2LIB)/lib/.libs -Wl,-rpath=$(H2LIB)/lib/.libs  -L$(H2LIB)/third-party/.libs -Wl,-rpath=$(H2LIB)/third-party/.libs

OBJS := server.o server_h2.o client.o client_h2.o


build: $(OBJS) 

	gcc $(GCC_FLAGS) $(INCLUDES) $(LINKS) -o h2.out main.c $(OBJS) $(LIBS) 

server.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o server.o server.c 

server_h2.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o server_h2.o server_h2.c 

client.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o client.o client.c 

client_h2.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o client_h2.o client_h2.c 


clean:

	rm -rf *.o *.out