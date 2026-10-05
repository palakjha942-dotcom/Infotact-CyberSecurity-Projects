#!/bin/bash
set -e

echo "[*] Running QuantumVault Week 4 Validation Suite..."

# Compile and run memory guard unit test
echo "[1/3] Testing memory locking and zeroization..."
gcc -Wall -Wextra -Iinclude tests/test_memory_guard.c src/memory_guard.c -o bin/test_memory_guard
./bin/test_memory_guard

# Verify CLI compilation
echo "[2/3] Verifying CLI argument parser..."
gcc -Wall -Wextra -Iinclude -c src/vault_cli.c -o /tmp/vault_cli.o
rm -f /tmp/vault_cli.o

# Verify Key Derivation compilation
echo "[3/3] Verifying PBKDF2 KDF module..."
gcc -Wall -Wextra -Iinclude -c src/key_derivation.c -o /tmp/key_derivation.o
rm -f /tmp/key_derivation.o

echo "[+] Week 4 verification suite passed!"
