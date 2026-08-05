PWD   := $(shell pwd)
obj-m := kmod_rust.o

default:
	make -C $(KDIR) LLVM=1 M=$(PWD) modules

clean:
	make -C $(KDIR) LLVM=1 M=$(PWD) clean