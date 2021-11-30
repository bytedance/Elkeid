
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

all: build rst

build:
	@echo "|---------------------------------|"
	@echo "| building HIDS pipe reader       |"
	@echo "|---------------------------------|"

# test program
rst_srcs := main.c
rst_objs := $(patsubst %.c,%.ou,$(rst_srcs))
$(rs_objs) :

%.ou: %.c
	$(QUIET_CC)$(CC) -I../include -std=gnu99 -c -o $@ $<

rst: $(rst_objs)
	@echo building test programs
	$(QUIET_CC)$(CC) -std=gnu99 -o rst $(rst_objs)
	@$(RM) ./main.ou

.PHONY: clean

clean:
	@$(RM) ./rst ./main.ou
