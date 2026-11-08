# Source-only real ELF fixture. The integration lane supplies CROSS_CC via
# conftest.find_rootfs_cross_compiler() and OUT inside pytest's temporary tree.
# Manual build: make CROSS_CC=/path/to/linux-musl-gcc OUT=/tmp/project-cross
# Nothing is executed: system/getenv/strcpy are genuine imported ABI calls.
# libc is deliberately not copied into this three-file project; builtin taint
# models describe those imports without opening thousands of libc functions.
ifndef OUT
$(error OUT must name a scratch directory outside the fixture source tree)
endif
ifndef CROSS_CC
$(error CROSS_CC must name a Linux musl cross compiler)
endif

CFLAGS := -O0 -g -fno-builtin -fno-stack-protector -fno-omit-frame-pointer -fno-optimize-sibling-calls
LIBDIR := $(OUT)/opt/cross/lib
APP := $(OUT)/usr/bin/cross-app
A := $(LIBDIR)/libcross_a.so
B := $(LIBDIR)/libcross_b.so
ANCHOR := -Wl,--section-start=.cross_identity=0x100000

all: $(APP) $(OUT)/etc/ld.so.conf

$(B): provider_b.c cross.h
	mkdir -p $(LIBDIR)
	$(CROSS_CC) $(CFLAGS) -shared -fPIC $(ANCHOR) -Wl,-soname,libcross_b.so -o $@ $<

$(A): provider_a.c cross.h $(B)
	$(CROSS_CC) $(CFLAGS) -shared -fPIC $(ANCHOR) -Wl,-soname,libcross_a.so -o $@ $< -L$(LIBDIR) -lcross_b -Wl,-rpath,/opt/cross/lib

$(APP): consumer.c cross.h $(A) $(B)
	mkdir -p $(dir $@)
	$(CROSS_CC) $(CFLAGS) -no-pie -o $@ $< -L$(LIBDIR) -lcross_a -Wl,-rpath,/opt/cross/lib -Wl,-rpath-link,$(LIBDIR) -Wl,--allow-shlib-undefined

$(OUT)/etc/ld.so.conf:
	mkdir -p $(dir $@)
	printf '/opt/cross/lib\n' > $@

.PHONY: all
