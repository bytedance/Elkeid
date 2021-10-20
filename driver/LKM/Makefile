MODULE_NAME		:= hids_driver
KERNEL_HEAD		:= $(if $(KVERSION),$(KVERSION),$(shell uname -r))
ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/init.o src/kprobe.o src/smith_hook.o src/anti_rootkit.o src/filter.o src/util.o src/core.o src/slot.o

MODULE_DIR		:= $(KBUILD_EXTMOD)
ldflags-y		+= -r -T $(MODULE_DIR)/kprobe.lds
ccflags-y		+= -I$(MODULE_DIR)/include
ccflags-y		+= -I$(MODULE_DIR)

UBUNTU_CHECK := $(shell bash $(MODULE_DIR)/ubuntu_check.sh)
CENTOS_CHECK := $(shell bash $(MODULE_DIR)/centos_check.sh)
D_ALIAS_CHECK := $(shell bash $(MODULE_DIR)/d_alias_check.sh)

ifeq ($(UBUNTU_CHECK),DISTRIB_ID=Ubuntu)
ccflags-y += -D UBUNTU_CHECK
endif

ifeq ($(CENTOS_CHECK),NAME="CentOS Linux")
ccflags-y += -D CENTOS_CHECK
endif

ifeq ($(D_ALIAS_CHECK),1)
ccflags-y += -D D_ALIAS_CHECK
endif

else

MODULE_DIR		:= $(shell pwd)
KERNEL_DIR		:= $(if $(wildcard /usr/src/kernels/$(KVERSION)),/usr/src/kernels/$(KVERSION),/lib/modules/$(KERNEL_HEAD)/build)

all:
	@echo "|-----------------------------------|"
	@echo "| building HIDS kernel module       |"
	@echo "|-----------------------------------|"
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) modules
	$(MAKE) -C test

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) clean
	$(MAKE) -C test clean

insmod:
	sudo insmod $(MODULE_NAME).ko

rmmod:
	sudo rmmod $(MODULE_NAME)

test:
	$(MAKE) -C test

endif
