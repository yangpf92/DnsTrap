# CFLAGS, LDFLAGS are defined in package.mk, which breaks
# the kernel module buidling process. So, let's create an
# independent file for this case.
include $(DIR_ZHONGHENG)/kmodule.mk

obj-m += dns_trap_module.o
dns_trap_module-objs = dns_packet.o dns_proc.o dnstrap.o dns_common.o

all: 
	$(MAKE) -C $(DIR_LINUX) M=$(CURDIR) modules

install:

clean:
	$(MAKE) -C $(DIR_LINUX) M=$(CURDIR) clean

romfs:
	$(ROMFSINST) dns_trap_module.ko /lib

lint:
	find . -iname "*.[ch]" | xargs clang-format-6.0 -i -style=file

.PHONY: all install clean romfs lint
