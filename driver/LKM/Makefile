MODULE_NAME		:= hids_driver
KERNEL_HEAD		:= $(if $(KVERSION),$(KVERSION),$(shell uname -r))
ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/init.o src/kprobe.o src/trace.o src/trace_buffer.o src/smith_hook.o src/anti_rootkit.o src/filter.o src/util.o

MODULE_DIR		:= $(KBUILD_EXTMOD)
ldflags-y		+= -r -T $(MODULE_DIR)/kprobe.lds
ccflags-y		+= -I$(MODULE_DIR)/include -I$(MODULE_DIR)

K_I_PATH		:= .
ifneq ($(wildcard /usr/src/kernels/$(KERNEL_HEAD)/include/.),)
K_I_PATH		+= /usr/src/kernels/$(KERNEL_HEAD)/include
endif
ifneq ($(wildcard /lib/modules/$(KERNEL_HEAD)/source/include/.),)
K_I_PATH		+= /lib/modules/$(KERNEL_HEAD)/source/include
endif
ifneq ($(wildcard /lib/modules/$(KERNEL_HEAD)/build/include/.),)
K_I_PATH		+= /lib/modules/$(KERNEL_HEAD)/build/include
endif

KMOD_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/module.h") /dev/null
KMOD_CORE_LAYOUT := $(shell sh -c "grep -s module_core\; $(KMOD_FILES)")
ifeq ($(KMOD_CORE_LAYOUT),)
ccflags-y += -D KMOD_CORE_LAYOUT
endif

KGID_CRED_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/cred.h") /dev/null
KGID_XIDS_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/uidgid.h") /dev/null
KGID_STRUCT_CHECK := $(shell sh -c "grep -s fsgid\; $(KGID_CRED_FILES) | grep kgid_t")
ifneq ($(KGID_STRUCT_CHECK),)
ccflags-y += -D KGID_STRUCT_CHECK
KGID_CONFIG_CHECK := $(shell sh -c "grep -s CONFIG_UIDGID_STRICT_TYPE_CHECKS $(KGID_XIDS_FILES)")
ifneq ($(KGID_CONFIG_CHECK),)
ccflags-y += -D KGID_CONFIG_CHECK
endif
endif

IPV6_FILES := $(shell find -L $(K_I_PATH) -path \*/net/sock.h) /dev/null
IPV6_SUPPORT := $(shell sh -c "grep -s skc_v6_daddr\; $(IPV6_FILES)")
ifneq ($(IPV6_SUPPORT),)
ccflags-y += -D IPV6_SUPPORT
endif

TRACE_EVENTS_HEADERS	:= $(shell find -L $(K_I_PATH) -path \*/linux/trace_events.h)
ifneq ($(TRACE_EVENTS_HEADERS),)
ccflags-y += -D SMITH_TRACE_EVENTS
endif

PROCFS_H_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/proc_fs.h") /dev/null
PROCFS_PDE_DATA := $(shell sh -c "grep -s pde_data $(PROCFS_H_FILES)")
ifneq ($(PROCFS_PDE_DATA),)
ccflags-y += -D SMITH_PROCFS_PDE_DATA
endif

TRACE_SEQ_FILES := $(shell find -L $(K_I_PATH) -path \*/linux/trace_seq.h) /dev/null
TRACE_SEQ_SEQ := $(shell sh -c "grep -sE struct[[:space:]]\+seq_buf[[:space:]]\+seq\; $(TRACE_SEQ_FILES)")
ifneq ($(TRACE_SEQ_SEQ),)
ccflags-y += -D SMITH_TRACE_SEQ
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
