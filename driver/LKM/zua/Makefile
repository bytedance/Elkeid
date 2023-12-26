
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

all: build libzua

#libzua static library
libzua_srcs := zua_parser.c zua_scanner.c zua_type.c
libzua_objs := $(patsubst %.c,%.ou,$(libzua_srcs))
$(libzua_objs) : hashmap.h  zua_parser.h  zua_parser_defs.h \
       		 zua_scanner.h  zua_scanner_defs.h  zua_type.h

%.ou: %.c
	$(QUIET_CC)$(CC) -I./ -std=gnu99 -c -o $@ $<

AR ?= ar
RANLIB ?= ranlib
libzua: $(libzua_objs)
	@echo building libzua
	@$(RM) -f libzua.a
	$(QUIET_AR)$(AR) r libzua.a $^
	$(QUIET_RANLIB)$(RANLIB) libzua.a

build:
	@echo "|---------------------------------|"
	@echo "| building libzua json parser     |"
	@echo "|---------------------------------|"

.PHONY: clean

clean:
	@$(RM) ./libzua.a ./*.ou
