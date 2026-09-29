CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 $(shell pkg-config --cflags fuse3)
LDFLAGS = $(shell pkg-config --libs fuse3) -loqs -lcrypto

all: quantum_vault

quantum_vault: src/vault_fuse.c src/dilithium_engine.c
	$(CC) $(CFLAGS) src/vault_fuse.c src/dilithium_engine.c -o quantum_vault $(LDFLAGS)

clean:
	rm -f quantum_vault
