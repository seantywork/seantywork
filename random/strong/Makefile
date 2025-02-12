GCC_FLAGS := -g -Wall


all: random.o

	gcc $(GCC_FLAGS) -I. -o random.out main.c random.o

random.o:
	
	gcc $(GCC_FLAGS) -c -I. -o random.o random.c 

clean:

	rm -rf *.out *.o