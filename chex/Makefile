
GCC_FLAGS := -g -Wall


OBJS := hex.o


all: $(OBJS)

	gcc $(GCC_FLAGS) -I. -o hex.out main.c $(OBJS)

hex.o:

	gcc $(GCC_FLAGS) -c -I. -o hex.o hex.c

clean:

	rm -r *.o *.a *.so *.out 