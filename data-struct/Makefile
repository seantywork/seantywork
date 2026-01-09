
GCC_FLAGS := -std=c99 -g -Wall
GCC_GNU_FLAGS := -std=gnu99 -g -Wall

all:

	gcc $(GCC_GNU_FLAGS) -c -I. -o c_struct.o c_struct.c

	gcc $(GCC_GNU_FLAGS) -c -I. -o interface.o interface.c

	gcc $(GCC_GNU_FLAGS) -I. -o main.out main.c c_struct.o interface.o 

	./main.out


clean:
	rm -r *.o *.a *.so *.out *.txt