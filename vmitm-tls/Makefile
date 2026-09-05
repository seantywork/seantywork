GCC_FLAGS := -Wall -O2 -g

all:

	gcc $(GCC_FLAGS) -I. -o mitm.out main.c -lcrypto -lssl


clean:
	rm -r *.o *.a *.so *.out