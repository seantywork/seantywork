
GCC_FLAGS := -std=c99 -g -Wall
GCC_GNU_FLAGS := -std=gnu99 -g -Wall

all:

	gcc $(GCC_GNU_FLAGS) -c -I. -o vector_string.o string.c

	gcc $(GCC_GNU_FLAGS) -c -I. -o vector_int.o int.c

	gcc $(GCC_GNU_FLAGS) -c -I. -o vector_inefficient.o inefficient.c

	gcc $(GCC_GNU_FLAGS) -c -I. -o interface.o interface.c

	gcc $(GCC_GNU_FLAGS) -I. -o main.out main.c vector_string.o vector_int.o vector_inefficient.o interface.o 

	./main.out


clean:
	rm -r *.o *.a *.so *.out