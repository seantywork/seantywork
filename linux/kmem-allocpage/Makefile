
KDIR ?= /lib/modules/$(shell uname -r)/build


PWD                   := $(shell pwd)
obj-m                 += lowlevel_mem_lkm.o
lowlevel_mem_lkm-objs := lowlevel_mem.o klib_llkd.o
EXTRA_CFLAGS          += -DDEBUG -Wformat=0 
  # above, we use -Wformat=0 here to turn Off some printk warnings reg the use
  # of %p instead of %016llx ...; we use %p so that we can see the actual virt
  # addr and not a hashed value (kernel security feature); it's ok here, but
  # don't do this in production.

all:
	@echo
	@echo '--- Building : KDIR=${KDIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} EXTRA_CFLAGS=${EXTRA_CFLAGS} ---'
	@echo
	make -C $(KDIR) M=$(PWD) modules
install:
	@echo
	@echo "--- installing ---"
	@echo
	make -C $(KDIR) M=$(PWD) modules_install
clean:
	@echo
	@echo "--- cleaning ---"
	@echo
	make -C $(KDIR) M=$(PWD) clean
	rm -f *~   # from 'indent'
