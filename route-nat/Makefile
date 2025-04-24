all: nats

clean:
	rm -rf *.o
	rm -rf *.out

nats: main.o nat_httpd.o
	gcc -o nats.out $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

nat_httpd.o: nat_httpd.c httpd.h
	gcc -c -o nat_httpd.o nat_httpd.c
