
ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC	= @echo '    '   CC $@;
	QUIET_CXX	= @echo '    '  CXX $@;
	QUIET_LINK	= @echo '  '   LINK $@;
	QUIET_LD	= @echo '    '   LD $@;
	QUIET_AR	= @echo '    '   AR $@;
	QUIET_RANLIB	= @echo '' RANLIB $@;
endif
endif

ifneq ($(KVARCH),)
	KV_ARCH = `echo $(KVARCH) | tr A-Z a-z`
	ARCH = $(shell echo $(KV_ARCH) | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
else
	ARCH = $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/')
endif

all: build libring

#libring static library
libring_srcs := kmod.c core.c safeboot.c \
		../zua/zua_scanner.c \
		../zua/zua_parser.c \
		../zua/zua_type.c
libring_objs := $(patsubst %.c,%.ou,$(libring_srcs))
$(libring_objs) : ../xfer/xfer.h ../LKM/include/trace.h \
		../zua/hashmap.h ../zua/zua_scanner.h \
		../zua/zua_parser.h ../zua/zua_parser_defs.h \
		../zua/zua_scanner_defs.h ../zua/zua_type.h

%.ou: %.c
	$(QUIET_CC)$(CC) -I../include -I../zua -std=gnu99 -c -g -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libring: $(libring_objs)
	@echo building libring
	@rm -f libring-$(ARCH).a
	$(QUIET_AR)$(AR) r libring-$(ARCH).a $^
	$(QUIET_RANLIB)$(RANLIB) libring-$(ARCH).a
	@$(RM) ./*.ou ../zua/*.ou

build:
	@echo "|---------------------------------|"
	@echo "| building HIDS ring library      |"
	@echo "|---------------------------------|"

.PHONY: clean

clean:
	@$(RM) ./libring-$(ARCH).a ./*.ou ../zua/*.ou
