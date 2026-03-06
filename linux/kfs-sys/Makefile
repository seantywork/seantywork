KDIR ?= /lib/modules/$(shell uname -r)/build

# Set FNAME_C to the kernel module name source filename (without .c)
FNAME_C := sysfs_if

PWD            := $(shell pwd)
obj-m          += ${FNAME_C}.o
EXTRA_CFLAGS   += -DDEBUG

all:
	@echo
	@echo '--- Building : KDIR=${KDIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} EXTRA_CFLAGS=${EXTRA_CFLAGS} ---'
	@echo
	make -C $(KDIR) M=$(PWD) modules
install:
	@echo
	@echo "--- installing ---"
	@echo " [First, invoke the 'make' ]"
	make
	@echo
	@echo " [Now for the 'sudo make install' ]"
	sudo make -C $(KDIR) M=$(PWD) modules_install
	sudo depmod
clean:
	@echo
	@echo "--- cleaning ---"
	@echo
	make -C $(KDIR) M=$(PWD) clean
	rm -f *~   # from 'indent'
