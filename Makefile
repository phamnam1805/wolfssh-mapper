CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g -O0
LDFLAGS = -shared -ldl

all: build/oob-handler.so build/send-oob build/syscall-capture.so

build/oob-handler.so: src/oob-handler.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/syscall-capture.so: src/syscall-capture.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/send-oob: src/send-oob.c
	@mkdir -p build
	$(CC) -Wall -Wextra -g -o $@ $<

clean:
	rm -rf build

.PHONY: all clean
