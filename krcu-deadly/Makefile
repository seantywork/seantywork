obj-m := rcudeadly.o

all:
ifneq ($(IACCEPTITWILLKILLKERNEL),y)
	@echo "needs 'IACCEPTITWILLKILLKERNEL=y' specified"
	@exit 1
endif
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean