CC      ?= gcc
AR      ?= ar
RANLIB  ?= ranlib
MAKE    ?= make
RM      ?= rm
MV      ?= mv
MKDIR   ?= mkdir

ifneq ($(KVARCH),)
	KV_ARCH = `echo $(KVARCH) | tr A-Z a-z`
	ARCH = $(shell echo $(KV_ARCH) | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
else
	ARCH = $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
endif

KV_MAINVERSION =  $(shell echo $(KVERSION) | awk -F'[-._]' '{print $$1}')
KV_PATCHLEVEL =  $(shell echo $(KVERSION) | awk -F'[-._]' '{print $$2}')
KV_SUBLEVEL =  $(shell echo $(KVERSION) | awk -F'[-._]' '{print $$3}')

UINCS := -I/usr/include				\
	 -I../libbpf                            \
	 -I../libbpf/include/uapi		\
	 -I../libbpf/include			\
	 -I. -I./hids/ -I./helper

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

# libebpf static library
EBPF_SRCS :=  consume.c load.c $(HELPER_PROGS)
EBPF_OBJS := $(patsubst %.c,%.eu,$(EBPF_SRCS))

%.eu: %.c
	$(CC) -Wall -O2 $(UINCS) -c -g -o $@ $<


all: libebpf-$(ARCH).a

libebpf-$(ARCH).a: $(EBPF_OBJS) $(HELPER_HEADS) ../xfer/ring.h
	@echo "|---------------------------------------|"
	@echo "| building libebpf.a ...                |"
	@echo "|---------------------------------------|"
	$(AR) r libebpf-$(ARCH).a $^
	$(RANLIB) libebpf-$(ARCH).a
	$(RM) -rf *.eu ./helper/*.eu

clean:
	$(RM) -rf ./*.eu ./helper/*.eu ./libebpf-$(ARCH).a
