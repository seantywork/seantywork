sha:

	gcc -g -O2 -c -o cmap_def.o cmap_def.c
	gcc -g -O2 -o cmap.out cmap.c cmap_def.o -lpthread -lcrypto -lssl

clean:
	
	rm -rf *.out *.o