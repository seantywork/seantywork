
GCC_FLAGS := -Wall

INCLUDES := -I../0xetc/0xgo/c-lib/go2c

LIBS := ../0xetc/0xgo/c-lib/go2c/go2c.so

LINKS := -L../0xetc/0xgo/c-lib/go2c

LOADS := -Wl,-rpath=../0xetc/0xgo/c-lib/go2c

all:

	gcc $(GCC_FLAGS) $(INCLUDES) $(LINKS) $(LOADS) -o go2c.out main.c $(LIBS)

clean:
	rm -r *.out