
GCC_FLAGS := -g -Wall

OBJS := sym.o


all: $(OBJS)

	gcc $(GCC_FLAGS) -I. -o sym.out main.c $(OBJS) -lssl -lcrypto


sym.o:

	gcc $(GCC_FLAGS) -c -I. -o sym.o sym.c


clean:

	rm -r *.o *.a *.so *.out *.data *.bin