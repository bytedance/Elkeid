MODULE_NAME		:= hids_driver
KERNEL_HEAD		:= $(if $(KVERSION),$(KVERSION),$(shell uname -r))
ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/init.o src/kprobe.o src/trace.o src/smith_hook.o src/anti_rootkit.o src/filter.o src/util.o

MODULE_DIR		:= $(KBUILD_EXTMOD)
ldflags-y		+= -r -T $(MODULE_DIR)/kprobe.lds
ccflags-y		+= -I$(MODULE_DIR)/include
ccflags-y		+= -I$(MODULE_DIR)

UBUNTU_CHECK := $(shell bash $(MODULE_DIR)/unbuntu_check.sh)

TRACE_EVENTS_HEADER		:=  /lib/modules/$(KERNEL_HEAD)/build/include/linux/trace_events.h
TRACE_EVENTS_HEADER_V   := $(TRACE_EVENTS_HEADER)
TRACE_EVENTS_HEADER_CHECK := $(shell test -e $(TRACE_EVENTS_HEADER_V))

ifeq ($(UBUNTU_CHECK),DISTRIB_ID=Ubuntu)
ccflags-y += -D UBUNTU_CHECK
endif

$(warning  $(TRACE_EVENTS_HEADER_CHECK))
ifeq ($(TRACE_EVENTS_HEADER_CHECK),$(TRACE_EVENTS_HEADER))
ccflags-y += -D SMITH_TRACE_EVENTS
endif
else
MODULE_DIR		:= $(shell pwd)
KERNEL_DIR		:= $(if $(KVERSION),/usr/src/kernels/$(KVERSION),/lib/modules/$(KERNEL_HEAD)/build)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) clean

insmod:
	sudo insmod $(MODULE_NAME).ko

rmmod:
	sudo rmmod $(MODULE_NAME)

endif
