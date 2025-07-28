CC := gcc
CFLAGS := -Wall -Wextra -O2
SOURCES := $(wildcard *.c)
BINARIES := $(SOURCES:.c=)

all: $(BINARIES)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINARIES)
