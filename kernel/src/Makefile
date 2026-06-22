obj-m += nomount.o
CFLAGS_nomount.o += -fno-optimize-sibling-calls

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
