CC = gcc
CFLAGS = -Wall -Wextra -D_FILE_OFFSET_BITS=64 -Iinclude $(shell pkg-config --cflags fuse3)
LDFLAGS = $(shell pkg-config --libs fuse3) -loqs -lcrypto -lssl

SRC = src/vault_fuse.c src/crypto_engine.c src/memory_guard.c
TARGET = bin/quantumvault

all: $(TARGET)

bin:
	mkdir -p bin

$(TARGET): $(SRC) | bin
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

test-memory: tests/test_memory_guard.c src/memory_guard.c | bin
	$(CC) -Wall -Wextra -Iinclude tests/test_memory_guard.c src/memory_guard.c -o bin/test_memory_guard
	./bin/test_memory_guard

clean:
	rm -rf bin
