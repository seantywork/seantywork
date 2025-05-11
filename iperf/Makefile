GCC_FLAGS := -Wall -O2

all: iperf_s.o

	gcc $(GCC_FLAGS) -I. -o iperf_s.out main.c iperf_s.o 


iperf_s.o: 

	gcc $(GCC_FLAGS) -c -I. -o iperf_s.o iperf_s.c

clean:
	rm -r *.o *.a *.so *.out