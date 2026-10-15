# Ascon-AEAD128
#
#   make          debug build: sanitizers + strict warnings
#   make strict   same, but every warning is an error
#   make release  optimized, hardened, no sanitizers
#   make clean    remove build output

CC     ?= cc
TARGET := ascon
SRC    := ascon.c

STD := -std=c11 -D_DEFAULT_SOURCE # _DEFAULT_SOURCE: getopt/getentropy on glibc

WARN := -Wall -Wextra -Wpedantic \
        -Wshadow -Wconversion -Wsign-conversion \
        -Wcast-qual -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes \
        -Wformat=2 -Wundef -Wvla -Wnull-dereference -Wimplicit-fallthrough

DEBUG   := -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
RELEASE := -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong

.PHONY: all debug strict release clean

all: debug

debug: CFLAGS := $(STD) $(WARN) $(DEBUG)
debug: $(TARGET)

strict: CFLAGS := $(STD) $(WARN) -Werror $(DEBUG)
strict: $(TARGET)

release: CFLAGS := $(STD) $(WARN) $(RELEASE)
release: $(TARGET)

$(TARGET): $(SRC) Makefile FORCE
	$(CC) $(CFLAGS) $(SRC) -o $@

FORCE:

clean:
	rm -rf $(TARGET) $(TARGET).dSYM
