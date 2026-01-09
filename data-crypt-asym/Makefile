
GCC_FLAGS := -g -Wall

OBJS := asym.o


all: $(OBJS)

	gcc $(GCC_FLAGS) -I. -o asym.out main.c $(OBJS) -lssl -lcrypto


asym.o:

	gcc $(GCC_FLAGS) -c -I. -o asym.o asym.c


clean:

	rm -r *.o *.a *.so *.out *.pem *.csr