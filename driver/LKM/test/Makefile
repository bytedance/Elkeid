
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

all: build libring rs

build:
	@echo "|---------------------------------|"
	@echo "| building ring slot (user mode)  |"
	@echo "|---------------------------------|"

# libring static library
libring_srcs := ring.c
libring_objs := $(patsubst %.c,%.ou,$(libring_srcs))
$(libring_objs) : ../include/ring.h ../include/slot.h

# test program
rs_srcs := main.c
rs_objs := $(patsubst %.c,%.ou,$(rs_srcs))
$(rs_objs) : ../include/ring.h ../include/slot.h

%.ou: %.c
	$(QUIET_CC)$(CC) -I../include -std=gnu99 -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libring: $(libring_objs)
	@echo building libring
	@rm -f libring.a
	$(QUIET_AR)$(AR) r libring.a $^
	$(QUIET_RANLIB)$(RANLIB) libring.a
	@$(RM) ./ring.ou

rs: libring $(rs_objs)
	@echo building test programs
	$(QUIET_CC)$(CC) -std=gnu99 -o rst $(rs_objs) libring.a
	@$(RM) ./main.ou

.PHONY: clean

clean:
	@$(RM) ./rst ./libring.a ./ring.ou ./main.ou
