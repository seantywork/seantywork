FLAGS := -g

all:
	gcc $(FLAGS) -o test.out main.c -lpthread
alignit:
	gcc $(FLAGS) -DALIGNIT -o test.out main.c -lpthread
clean:
	rm -rf *.o *.out 