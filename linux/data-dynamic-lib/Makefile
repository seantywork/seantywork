all:

	@echo "dl"


build: libsuperdym.so

	gcc -g -O2 -o test.out main.c -ldl

libsuperdym.so:
	gcc -Wall -g -O2 -c -fPIC -o super_dym.o super_dym.c
	gcc -g -O2 -shared -o libsuperdym.so super_dym.o

clean:
	rm -rf *.so *.out *.o