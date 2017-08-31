target := usb

CFLAGS += `pkg-config --cflags openssl` -MMD -MP -O3 -g -std=gnu11 -Wall -Wextra -Wpedantic
LDFLAGS += `pkg-config --libs openssl`

.DEFAULT_GOAL := $(target)

sources := $(shell find . -type f -name '*.c')
dependencies := $(patsubst %.c, %.d, $(sources))
objects := $(patsubst %.c, %.o, $(sources))

$(target): $(objects)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

-include $(dependencies)