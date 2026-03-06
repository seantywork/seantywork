GCC_FLAGS := -Wall -O2 -g

all: tenk.o

	gcc $(GCC_FLAGS) -I. -o tenk.out main.c tenk.o -lpthread


tenk.o: 

	gcc $(GCC_FLAGS) -c -I. -o tenk.o tenk.c

clean:
	rm -r *.o *.a *.so *.out