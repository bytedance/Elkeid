
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

all: build libring rst

#libring static library
libring_srcs := ring.c
libring_objs := $(patsubst %.c,%.ou,$(libring_srcs))
$(libring_objs) : ../include/xfer.h ../include/trace.h

# test program
rst_srcs := main.c
rst_objs := $(patsubst %.c,%.ou,$(rst_srcs))
$(rs_objs) :

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

rst: libring $(rst_objs)
	@echo building test programs
	$(QUIET_CC)$(CC) -std=gnu99 -o rst $(rst_objs) libring.a
	@$(RM) ./main.ou

build:
	@echo "|---------------------------------|"
	@echo "| building HIDS pipe reader       |"
	@echo "|---------------------------------|"

.PHONY: clean

clean:
	@$(RM) ./rst ./libring.a ./main.ou ./ring.ou
