CLANG   ?= clang
LLC     ?= llc
OPT     ?= opt  #/usr/lib/llvm-14/bin/opt
DIS     ?= llvm-dis
RM      ?= rm
CC      ?= gcc
MAKE    ?= make
OBJDUMP ?= llvm-objdump
BPFTOOL ?= bpftool

ARCH    ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/x86/')

KINCS := -I./kernel/libbpf/include		\
	 -I./kernel				\
	 -I./kernel/$(ARCH)			\
	 -I./

UINCS := -I/usr/include				\
	 -I./libbpf/include/uapi		\
         -I./kernel/libbpf/include		\
	 -I./libbpf/include			\
	 -I. -I./helper

CFLAGS_KV :=					\
	-g -O2 -Wall                            \
	-emit-llvm -target bpf                  \
	-D__KERNEL__                            \
	-D__TARGET_ARCH_$(ARCH)                 \
	-D__NATIVE_EBPF__

ifneq ($(KV_VERSION),)
CFLAGS_KV += -DKV_VERSION=$(KV_VERSION)
endif
ifneq ($(KV_PATCHLEVEL),)
CFLAGS_KV += -DKV_PATCHLEVEL=$(KV_PATCHLEVEL)
endif
ifneq ($(KV_SUBLEVEL),)
CFLAGS_KV += -DKV_SUBLEVEL=$(KV_SUBLEVEL)
endif
ifneq ($(KV_EXTRAVERSION),)
CFLAGS_KV += -DKV_EXTRAVERSION=$(KV_EXTRAVERSION)
endif

CFLAGS_BTF := $(CFLAGS_KV)
CFLAGS_BPF := $(CFLAGS_KV) -DBPF_NO_PRESERVE_ACCESS_INDEX

HELPER_PROGS := ./helper/errno_helpers.c	\
		./helper/trace_helpers.c	\
		./helper/btf_helpers.c		\
		./helper/map_helpers.c		\
		./helper/uprobe_helpers.c	\
		./helper/syscall_helpers.c

HELPER_HEADS := ./helper/errno_helpers.h	\
		./helper/trace_helpers.h	\
		./helper/btf_helpers.h		\
		./helper/map_helpers.h		\
		./helper/uprobe_helpers.h	\
		./helper/syscall_helpers.h

all: hids.bpf.o hids.btf.o driver.bpf driver.btf consume

hids.btf.o: hids.bpf.c hids/hids.h
	@echo "|---------------------------------------|"
	@echo "| building hids ebpf (BTF) ...          |"
	@echo "|---------------------------------------|"
	$(CLANG) $(CFLAGS_BTF) $(KINCS) $() -O2 -c $< -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux               | \
	$(DIS)                                         | \
	$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o hids.btf.o
	$(BPFTOOL) gen skeleton hids.btf.o > hids.btf.h

hids.bpf.o: hids.bpf.c hids/hids.h
	@echo "|---------------------------------------|"
	@echo "| building hids ebpf (bpf) ...          |"
	@echo "|---------------------------------------|"
	$(CLANG) $(CFLAGS_BPF) $(KINCS) -O2 -c $< -o - | \
	$(OPT) -O2 -mtriple=bpf-pc-linux               | \
	$(DIS)                                         | \
	$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o hids.bpf.o
	$(BPFTOOL) gen skeleton hids.bpf.o > hids.bpf.h

kernel/$(ARCH)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > kernel/$(ARCH)/vmlinux.h

consume: libbpf/src/libbpf.a consume.c xfer.c
	@echo "|---------------------------------------|"
	@echo "| building consume ...                  |"
	@echo "|---------------------------------------|"
	$(CC) -Wall -O2 $(UINCS) -o consume consume.c xfer.c $(HELPER_PROGS) ./libbpf/src/libbpf.a -lelf -lz -lrt

driver.btf: libbpf/src/libbpf.a hids.bpf.o xfer.c driver.btf.c $(HELPER_HEADS)
	@echo "|---------------------------------------|"
	@echo "| building hids agent plugin (BTF) ...  |"
	@echo "|---------------------------------------|"
	$(CC) -Wall -O2 $(UINCS) -o driver.btf driver.btf.c xfer.c $(HELPER_PROGS) ./libbpf/src/libbpf.a -lelf -lz -lrt

driver.bpf: libbpf/src/libbpf.a hids.bpf.o xfer.c driver.bpf.c $(HELPER_HEADS)
	@echo "|---------------------------------------|"
	@echo "| building hids agent plugin (BPF) ...  |"
	@echo "|---------------------------------------|"
	$(CC) -Wall -O2 $(UINCS) -o driver.bpf driver.bpf.c xfer.c $(HELPER_PROGS) ./libbpf/src/libbpf.a -lelf -lz -lrt

libbpf/src/libbpf.a:
	@echo "|---------------------------------------|"
	@echo "| building libbpf ...                   |"
	@echo "|---------------------------------------|"
	$(MAKE) -C libbpf/src

clean:
	$(RM) -rf hids.*.o hids.*.h driver.btf driver.bpf consume
	$(MAKE) -C libbpf/src clean
