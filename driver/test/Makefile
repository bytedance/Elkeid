
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

all: build ../hids/elkeid-$(ARCH)

# test program
elkeid_srcs := main.c
elkeid_objs := $(patsubst %.c,%.ou,$(elkeid_srcs))

%.ou: %.c
	$(QUIET_CC)$(CC) -I../include -I../zua -std=gnu99 -c -g -o $@ $<

../hids/elkeid-$(ARCH): $(elkeid_objs) ../hids/elkeid-$(ARCH).a
	@echo building test programs
	$(QUIET_CC)$(CC) -std=gnu99 -o ../hids/elkeid-$(ARCH) \
	$(elkeid_objs) ../hids/elkeid-$(ARCH).a  -lelf -lz -lrt
	@$(RM) ./main.ou

build:
	@echo "|---------------------------------|"
	@echo "| building ELKEID/HIDS consumer   |"
	@echo "|---------------------------------|"

.PHONY: clean

clean:
	@$(RM) ../hids/elkeid-$(ARCH) ./main.ou
