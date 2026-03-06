GCC_FLAGS := -std=gnu99 -g -Wall


all: wc.o

	gcc $(GCC_FLAGS) -I. -o wc.out main.c wc.o


wc.o: 

	gcc $(GCC_FLAGS) -c -I. -o wc.o wc.c

clean:
	rm -r *.o *.a *.so *.out