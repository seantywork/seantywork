GCC_FLAGS := -Wall

GCC_OBJ_FLAGS := -Wall -c

INCLUDES := -I.

LIBS := -lrt -lpthread -lpigpio -lc 

SPI_OBJ := spi.o 


all: $(SPI_OBJ)

	gcc $(GCC_FLAGS) $(INCLUDES) -o spi.out main.c $(SPI_OBJ) $(LIBS)



spi.o: 


	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o spi.o spi.c 


clean:


	rm -rf *.o *.out