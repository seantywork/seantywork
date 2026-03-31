PWD          := $(shell pwd)
obj-m        += kqueue_cc.o
obj-m        += kqueue_cc_wq.o


all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
install:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules_install
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean