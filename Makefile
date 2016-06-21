obj-m := liinux.o
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
all:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.symvers *.mod.* *.order .*.cmd

