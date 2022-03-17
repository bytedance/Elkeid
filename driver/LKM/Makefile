MODULE_NAME		:= hids_driver
KERNEL_HEAD		:= $(if $(KVERSION),$(KVERSION),$(shell uname -r))
ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/init.o src/kprobe.o src/trace.o src/trace_buffer.o src/smith_hook.o src/anti_rootkit.o src/filter.o src/util.o

MODULE_DIR		:= $(KBUILD_EXTMOD)
ldflags-y		+= -r -T $(MODULE_DIR)/kprobe.lds
ccflags-y		+= -I$(MODULE_DIR)/include -I$(MODULE_DIR)

K_S_PATH	:= /lib/modules/$(KERNEL_HEAD)/source/include
K_B_PATH	:= /lib/modules/$(KERNEL_HEAD)/build/include

KMOD_CORE_LAYOUT := $(shell bash -c "grep -s module_core\; $(K_S_PATH)/linux/module.h $(K_B_PATH)/linux/module.h")
ifeq ($(KMOD_CORE_LAYOUT),)
ccflags-y += -D KMOD_CORE_LAYOUT
endif

KGID_STRUCT_CHECK	:= $(shell bash -c "grep -s fsgid\; $(K_S_PATH)/linux/cred.h $(K_B_PATH)/linux/cred.h | grep kgid_t")
ifneq ($(KGID_STRUCT_CHECK),)
ccflags-y += -D KGID_STRUCT_CHECK
KGID_CONFIG_CHECK	:= $(shell bash -c "grep -s CONFIG_UIDGID_STRICT_TYPE_CHECKS $(K_S_PATH)/linux/uidgid.h $(K_B_PATH)/linux/uidgid.h")
ifneq ($(KGID_CONFIG_CHECK),)
ccflags-y += -D KGID_CONFIG_CHECK
endif
endif

IPV6_SUPPORT	:= $(shell bash -c "grep -s skc_v6_daddr\; $(K_S_PATH)/net/sock.h $(K_B_PATH)/net/sock.h")
ifneq ($(IPV6_SUPPORT),)
ccflags-y += -D IPV6_SUPPORT
endif

TRACE_EVENTS_HEADER		:=  /lib/modules/$(KERNEL_HEAD)/build/include/linux/trace_events.h
TRACE_EVENTS_HEADER_V   := $(TRACE_EVENTS_HEADER)
TRACE_EVENTS_HEADER_CHECK := $(shell test -e $(TRACE_EVENTS_HEADER_V))

ifeq ($(TRACE_EVENTS_HEADER_CHECK),$(TRACE_EVENTS_HEADER))
ccflags-y += -D SMITH_TRACE_EVENTS
endif

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
