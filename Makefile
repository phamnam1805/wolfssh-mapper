CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -shared -ldl

all: build/oob-handler.so build/send-oob

build/oob-handler.so: src/oob-handler.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/send-oob: src/send-oob.c
	@mkdir -p build
	$(CC) -Wall -Wextra -o $@ $<

clean:
	rm -rf build

.PHONY: all clean
