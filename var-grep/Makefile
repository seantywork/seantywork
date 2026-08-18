
GCC_FLAGS := -std=gnu99 -g -Wall


all: grep.o

	gcc $(GCC_FLAGS) -I. -o grep.out main.c grep.o


grep.o: 

	gcc $(GCC_FLAGS) -c -I. -o grep.o grep.c

clean:
	rm -r *.o *.a *.so *.out