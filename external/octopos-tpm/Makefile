obj-m := octopos-tpm.o

MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}

SRC := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules

install: all
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install
	depmod -a

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) clean
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers

