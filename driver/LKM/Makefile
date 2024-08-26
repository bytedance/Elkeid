MODULE_NAME		:= elkeid
KERNEL_HEAD		:= $(if $(KVERSION),$(KVERSION),$(shell uname -r))

ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/init.o src/trace.o src/trace_buffer.o src/smith_hook.o src/anti_rootkit.o src/filter.o src/util.o src/memcache.o

MODULE_DIR		:= $(KBUILD_EXTMOD)
ccflags-y		+= -I$(MODULE_DIR)/include -I$(MODULE_DIR)

K_I_PATH		:= .
ifneq ($(wildcard $(srctree)/include/.),)
K_I_PATH                += $(srctree)/include
endif

ifneq ($(wildcard /usr/src/$(KERNEL_HEAD)/include/.),)
K_I_PATH		+= /usr/src/$(KERNEL_HEAD)/include
endif
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
KMOD_MODULE_MEM := $(shell sh -c "grep -s struct\ module_memory $(KMOD_FILES)")
ifeq ($(KMOD_MODULE_MEM),)
ifeq ($(KMOD_CORE_LAYOUT),)
ccflags-y += -D KMOD_CORE_LAYOUT
endif
else
ccflags-y += -D KMOD_MODULE_MEM
endif

CLASS_H_FILES := $(shell find -L $(K_I_PATH) -path \*/linux/device/class.h)
CLASS_H_FILES += $(shell find -L $(K_I_PATH) -path \*/linux/device.h) /dev/null
CLASS_CREATE_HAVE_OWNER := $(shell sh -c "grep -sE [[:space:]]+class_create $(CLASS_H_FILES) | grep owner\,")
ifneq ($(CLASS_CREATE_HAVE_OWNER),)
ccflags-y += -D CLASS_CREATE_HAVE_OWNER
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

UACCESS_FILES := $(shell find -L $(K_I_PATH) -path \*/asm-generic/uaccess.h) /dev/null
UACCESS_SUPPORT := $(shell sh -c "grep -sE define[[:space:]]\+access_ok $(UACCESS_FILES) | grep type")
ifneq ($(UACCESS_SUPPORT),)
ccflags-y += -D UACCESS_TYPE_SUPPORT
endif

FS_H_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/fs.h") /dev/null
FS_OP_ITERATE := $(shell sh -c "grep -s \(\*iterate\) $(FS_H_FILES)")
FS_OP_ITERATE_SHARED := $(shell sh -c "grep -s \(\*iterate_shared\) $(FS_H_FILES)")
ifneq ($(FS_OP_ITERATE),)
ccflags-y += -D SMITH_FS_OP_ITERATE
endif
ifneq ($(FS_OP_ITERATE_SHARED),)
ccflags-y += -D SMITH_FS_OP_ITERATE_SHARED
endif

PROCFS_H_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/proc_fs.h") /dev/null
PROCNS_H_FILES := $(shell find -L $(K_I_PATH) -path "*/linux/proc_ns.h") /dev/null
MNTNS_OPS_PROCFS := $(shell sh -c "grep -s mntns_operations $(PROCFS_H_FILES)")
MNTNS_OPS_PROCNS := $(shell sh -c "grep -s mntns_operations $(PROCNS_H_FILES)")
ifeq ($(MNTNS_OPS_PROCFS),)
ifeq ($(MNTNS_OPS_PROCNS),)
ccflags-y += -D SMITH_HAVE_NO_MNTNS_OPS
endif
else
ccflags-y += -D SMITH_HAVE_MNTNS_PROCFS
endif
MNTNS_OPS_INUM := $(shell sh -c "grep -s \(\[\*\]inum\) $(PROCFS_H_FILES) $(PROCNS_H_FILES)")
ifneq ($(MNTNS_OPS_INUM),)
ccflags-y += -D SMITH_HAVE_MNTNS_OPS_INUM
endif

FCHECK_H_FILES := $(shell find -L $(K_I_PATH) -path \*/linux/fdtable.h) /dev/null
FCHECK_SUPPORT := $(shell sh -c "grep -sE \\*[[:space:]]*fcheck_files $(FCHECK_H_FILES)")
ifneq ($(FCHECK_SUPPORT),)
ccflags-y += -D SMITH_HAVE_FCHECK_FILES
endif

USER_MSGHDR_FILES := $(shell find -L $(K_I_PATH) -path \*/linux/socket.h) /dev/null
USER_MSGHDR_STRUT := $(shell sh -c "grep -sE struct[[:space:]]\+user_msghdr[[:space:]]\+\{ $(USER_MSGHDR_FILES)")
ifeq ($(USER_MSGHDR_STRUT),)
ccflags-y += -D USER_MSGHDR_SUPPORT
endif

MM_GUP_FILES := $(shell find -L $(K_I_PATH) -path \*/linux/mm.h) /dev/null
MM_GUP_STRUT := $(shell sh -c "grep -sE -A2 long[[:space:]]\+get_user_pages[\(\)] $(MM_GUP_FILES) | grep gup_flags")
ifneq ($(MM_GUP_STRUT),)
ccflags-y += -D MM_GUP_FLAGS_SUPPORT
endif

else

MODULE_DIR		:= $(shell pwd)
ifneq ($(wildcard /lib/modules/$(KERNEL_HEAD)/build),)
KERNEL_DIR		:= /lib/modules/$(KERNEL_HEAD)/build
else ifneq ($(wildcard /usr/src/kernels/$(KERNEL_HEAD)),)
KERNEL_DIR		:= /usr/src/kernels/$(KERNEL_HEAD)
else ifneq ($(wildcard /usr/src/$(KERNEL_HEAD)),)
KERNEL_DIR		:= /usr/src/$(KERNEL_HEAD)
else
$(error Kernel header files related to $(KERNEL_HEAD) not found)
endif

all:
	@echo "|-----------------------------------|"
	@echo "| building HIDS kernel module       |"
	@echo "|-----------------------------------|"
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) modules
ifneq ($(BATCH), true)
	$(MAKE) -C zua
	$(MAKE) -C test
endif

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(MODULE_DIR) clean
	$(MAKE) -C zua clean
	$(MAKE) -C test clean

insmod:
	sudo insmod $(MODULE_NAME).ko

rmmod:
	sudo rmmod $(MODULE_NAME)

test:
	$(MAKE) -C zua
	$(MAKE) -C test

zua:
	$(MAKE) -C zua

endif
