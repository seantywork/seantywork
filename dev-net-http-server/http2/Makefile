GCC_FLAGS := -Wall -g

GCC_OBJ_FLAGS := -Wall -c

H2LIB := nghttp2-1.70.0

INCLUDES := -I./include -I$(H2LIB)/lib/includes

LIBS := -lpthread -lssl -lcrypto -lnghttp2

LINKS := -L$(H2LIB)/lib/.libs -Wl,-rpath=$(H2LIB)/lib/.libs

OBJS := server.o server_h2.o


build: $(OBJS) 

	gcc $(GCC_FLAGS) $(INCLUDES) $(LINKS) -o h2.out main.c $(OBJS) $(LIBS) 

server.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o server.o server.c 

server_h2.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o server_h2.o server_h2.c 



clean:

	rm -rf *.o *.out