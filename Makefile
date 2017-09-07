target := usb

#CFLAGS += `pkg-config --cflags openssl` -MMD -MP -O3 -g -std=gnu11 -Wall -Wextra -Wpedantic -I.
CFLAGS += `pkg-config --cflags openssl` -MMD -MP -O3 -g -std=gnu11 -I.
LDFLAGS += `pkg-config --libs openssl` -pthread

.DEFAULT_GOAL := $(target)

sources := $(shell find . -name '*.c') cmdline.c
dependencies := $(patsubst %.c, %.d, $(sources))
objects := $(patsubst %.c, %.o, $(sources))

$(target): $(objects)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

cmdline.c: ccid.ggo
	<$< gengetopt

-include $(dependencies)