CLANG   ?= clang
LLC     ?= llc
OPT     ?= opt  #/usr/lib/llvm-14/bin/opt
DIS     ?= llvm-dis

CC      ?= gcc
AR      ?= ar
RANLIB  ?= ranlib
MAKE    ?= make
OBJDUMP ?= llvm-objdump
OBJCOPY ?= llvm-objcopy
BPFTOOL ?= bpftool
RM      ?= rm
MV      ?= mv
MKDIR   ?= mkdir

ifneq ($(KVERSION),)

  ifneq ($(KVARCH),)
	KV_ARCH = `echo $(KVARCH) | tr A-Z a-z`
	ARCH = $(shell echo $(KV_ARCH) | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
  else ifneq ($(findstring aarch64, $(KVERSION)),)
	ARCH = arm64
  else ifneq ($(findstring arm64, $(KVERSION)),)
	ARCH = arm64
  else ifneq ($(findstring amd64, $(KVERSION)),)
	ARCH = amd64
  else ifneq ($(findstring x86_64, $(KVERSION)),)
	ARCH = amd64
  else
	ARCH = amd64
  endif

else

  ARCH   ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
  KVERSION = $(shell uname -r)

endif

KV_MAINVERSION =  $(shell echo $(KVERSION) | awk -F'[-._]' '{print $$1}')
KV_PATCHLEVEL =  $(shell echo $(KVERSION) | awk -F'[-._]' '{print $$2}')
KV_SUBLEVEL =  $(shell echo $(KVERSION) | awk -F'[-._]' '{print $$3}')

KINCS := -I../ebpf -I./inc/ -I./inc/$(ARCH) -I../

CFLAGS_KV := -DXFER_EBPF=1                      \
	-g -O2 -Wall                            \
	-emit-llvm -target bpf                  \
	-D__KERNEL__                            \
	-D__NATIVE_EBPF__

CFLAGS_KV += -DKV_VERSION=$(KVERSION)
CFLAGS_KV += -DKV_MAINVERSION=$(KV_MAINVERSION)
CFLAGS_KV += -DKV_PATCHLEVEL=$(KV_PATCHLEVEL)
CFLAGS_KV += -DKV_SUBLEVEL=$(KV_SUBLEVEL)

ifeq ($(ARCH), amd64)
  CFLAGS_KV += -D__TARGET_ARCH_x86
else
  CFLAGS_KV += -D__TARGET_ARCH_$(ARCH)
endif

ifeq ($(TASK_PID_LINK),)
  TASK_PID_LINK := $(shell sh -c "grep -s struct\ pid_link inc/$(ARCH)/vmlinux-$(KVERSION).h")
endif
ifneq ($(TASK_PID_LINK),)
  CFLAGS_KV += -DTASK_HAS_PID_LINK
endif

ifeq ($(BUILD_DIR),)
	BUILD_DIR = ../hids
endif

CFLAGS_BTF := $(CFLAGS_KV)
CFLAGS_BPF := $(CFLAGS_KV) -DBPF_NO_PRESERVE_ACCESS_INDEX

all: prepare elkeid.bpf.o elkeid.btf.o

prepare:
	$(MKDIR) -p $(BUILD_DIR)

test:
	@echo KVERSION: $(KVERSION) ARCH: $(ARCH)
	@echo KV_VERSION: $(KV_MAINVERSION)
	@echo KV_PATCHLEVEL: $(KV_PATCHLEVEL)
	@echo KV_SUBLEVEL: $(KV_SUBLEVEL)
	@echo CFLAGS_KV: $(CFLAGS_KV)
	@echo BUILD_DIR: $(BUILD_DIR)

inc/$(ARCH)/vmlinux-$(KVERSION).h:
	mkdir -p inc/$(ARCH)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > inc/$(ARCH)/vmlinux-$(KVERSION).h

elkeid.btf.o: hids.c inc/$(ARCH)/vmlinux-$(KVERSION).h
	@echo "|---------------------------------------|"
	@echo "| building elkeid ebpf (BTF) ...        |"
	@echo "|---------------------------------------|"
	$(CLANG) $(CFLAGS_BTF) $(KINCS) $() -O2 -c $< -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux               | \
	$(DIS)                                         | \
	$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $(BUILD_DIR)/elkeid.btf.o
	# $(BPFTOOL) gen skeleton $(BUILD_DIR)/elkeid.btf.o > $(BUILD_DIR)/hids.btf-$(KVERSION).h
	$(MV) $(BUILD_DIR)/elkeid.btf.o $(BUILD_DIR)/elkeid.btf-$(KVERSION).o

elkeid.bpf.o: hids.c inc/$(ARCH)/vmlinux-$(KVERSION).h
	@echo "|---------------------------------------|"
	@echo "| building elkeid ebpf (bpf) ...        |"
	@echo "|---------------------------------------|"
	$(CLANG) $(CFLAGS_BPF) $(KINCS) -O2 -c $< -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux               | \
	$(DIS)                                         | \
	$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $(BUILD_DIR)/elkeid.bpf.o
	# $(BPFTOOL) gen skeleton $(BUILD_DIR)/elkeid.bpf.o > $(BUILD_DIR)/hids.bpf-$(KVERSION).h
	# echo remove BTF.ext sections from BPF target
	$(OBJCOPY) -R .BTF.ext -R .BTF.ext.rel $(BUILD_DIR)/elkeid.bpf.o
	$(MV) $(BUILD_DIR)/elkeid.bpf.o $(BUILD_DIR)/elkeid.bpf-$(KVERSION).o

clean:
	$(RM) -rf $(BUILD_DIR)/hids.bpf-$(KVERSION)* $(BUILD_DIR)/elkeid.bpf-$(KVERSION)*
	$(RM) -rf $(BUILD_DIR)/hids.btf-$(KVERSION)* $(BUILD_DIR)/elkeid.btf-$(KVERSION)*

