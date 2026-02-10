
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

all: build libxfer

#libxfer static library
libxfer_srcs := xfer.c
libxfer_objs := $(patsubst %.c,%.ou,$(libxfer_srcs))
$(libxfer_objs) : xfer.h

%.ou: %.c
	$(QUIET_CC)$(CC) -I.. -std=gnu99 -c -g -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libxfer: $(libxfer_objs)
	@echo building libxfer
	@rm -f libxfer-$(ARCH).a
	$(QUIET_AR)$(AR) r libxfer-$(ARCH).a $^
	$(QUIET_RANLIB)$(RANLIB) libxfer-$(ARCH).a
	@$(RM) ./xfer.ou

build:
	@echo "|---------------------------------|"
	@echo "| building ELKEID xfer library    |"
	@echo "|---------------------------------|"

.PHONY: clean

clean:
	@$(RM) ./libxfer-$(ARCH).a ./xfer.ou
