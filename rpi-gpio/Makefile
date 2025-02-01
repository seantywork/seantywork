GCC_FLAGS := -Wall

GCC_OBJ_FLAGS := -Wall -c

INCLUDES := -I.

LIBS := -lrt -lpthread -lpigpio -lc 

GPIO_OBJ := gpio.o


all: 

	gcc $(GCC_FLAGS) $(INCLUDES) -o gpio.out main.c  $(LIBS)



clean:


	rm -rf *.o *.out