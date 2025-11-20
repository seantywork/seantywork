obj-m := kproc.o

all:
	make -C user
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C user clean
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean