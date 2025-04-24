GCC_FLAGS := -g -Wall -O2


all: ncat.o

	gcc $(GCC_FLAGS) -I. -o ncat.out main.c ncat.o -lpthread


ncat.o: 

	gcc $(GCC_FLAGS) -c -I. -o ncat.o ncat.c

clean:
	rm -r *.o *.a *.so *.out