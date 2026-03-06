all:

	gcc -c -fPIC -o c2go.o c2go.c

	gcc -shared -o libc2go.so c2go.o

clean:
	rm -r *.so *.o