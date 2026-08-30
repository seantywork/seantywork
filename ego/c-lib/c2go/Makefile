all:

	gcc -g -O2 -c -fPIC -o c2go.o c2go.c
	gcc -shared -o libc2go.so c2go.o
	/bin/cp -Rf libc2go.so dynamic/libc2go.so
	gcc -g -O2 -c -o c2go.o c2go.c
	ar rcs libc2go.a c2go.o
	/bin/cp -Rf libc2go.a static/libc2go.a

clean:
	rm -rf  *.so *.a *.o