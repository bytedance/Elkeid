CFLAGS += -D_GNU_SOURCE -std=gnu99
CFLAGS += -static-libgcc -lgcc
CFLAGS += -I c-runtime
CFLAGS += -fno-common -fno-stack-protector -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables
PORTABLE = -pie -fPIE -fno-builtin -nostdlib -Wl,--no-dynamic-linker

all:
	$(CC) $(CFLAGS) $(PORTABLE) -o python_caller main.c c-runtime/*.c c-runtime/printf/printf.c