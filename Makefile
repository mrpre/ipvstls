obj-y := ip_vs_tls/ tlsparser/
KDIR := /lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules

