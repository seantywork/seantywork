GCC_FLAGS := -std=c99 -g -Wall


all: cat.o

	gcc $(GCC_FLAGS) -I. -o cat.out main.c cat.o


cat.o: 

	gcc $(GCC_FLAGS) -c -I. -o cat.o cat.c

clean:
	rm -r *.o *.a *.so *.out