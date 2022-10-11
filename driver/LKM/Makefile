MODULE_NAME		:= hids_driver
KERNEL_HEAD		:= $(if $(KVERSION),$(KVERSION),$(shell uname -r))
ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/init.o src/trace.o src/trace_buffer.o src/smith_hook.o src/anti_rootkit.o src/filter.o src/util.o

MODULE_DIR		:= $(KBUILD_EXTMOD)
ccflags-y		+= -I$(MODULE_DIR)/include -I$(MODULE_DIR)

include $(MODULE_DIR)/configs.mk

else

MODULE_DIR		:= $(shell pwd)
KERNEL_DIR		:= $(if $(wildcard /usr/src/kernels/$(KERNEL_HEAD)),/usr/src/kernels/$(KERNEL_HEAD),/lib/modules/$(KERNEL_HEAD)/build)

all:
	@echo "|-----------------------------------|"
	@echo "| building HIDS kernel module       |"
	@echo "|-----------------------------------|"
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) modules
ifneq ($(BATCH), true)
	$(MAKE) -C test
endif

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

