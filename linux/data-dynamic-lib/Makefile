all:

	@echo "dl"


build:

	gcc -o test.out main.c -ldl


lib:

	gcc -Wall -c -fpic -o super_dym.o super_dym.c

	gcc -shared -o libsuperdym.so super_dym.o

