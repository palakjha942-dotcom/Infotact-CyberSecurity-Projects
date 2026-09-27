CC = gcc
CFLAGS = -Wall -O2 `pkg-config fuse3 --cflags`
LDFLAGS = `pkg-config fuse3 --libs` -loqs -lcrypto

all: quantum_vault test_kyber

quantum_vault: src/quantum_vault.c
	$(CC) $(CFLAGS) src/quantum_vault.c $(LDFLAGS) -o quantum_vault

test_kyber: src/test_kyber.c
	$(CC) -O2 src/test_kyber.c -loqs -lcrypto -o test_kyber

test: all
	chmod +x tests/run_tests.sh
	./tests/run_tests.sh

clean:
	rm -f quantum_vault test_kyber tests/quantum_vault tests/test_kyber
