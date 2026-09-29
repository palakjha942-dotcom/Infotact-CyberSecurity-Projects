#!/bin/bash
set -e

VAULT_DIR="/tmp/vault_test_mount"
BACKING_DIR="/tmp/quantum_vault_backing"

echo "=== QuantumVault Week 3 Integration & Tamper Test ==="

# 1. Clean previous runs
fusermount3 -u "$VAULT_DIR" 2>/dev/null || true
rm -rf "$VAULT_DIR" "$BACKING_DIR"
mkdir -p "$VAULT_DIR"

# 2. Build binaries
make clean && make

# 3. Mount filesystem in background
./quantum_vault "$VAULT_DIR" &
VAULT_PID=$!
sleep 2

# 4. Write test secret
TEST_STR="TopSecret_Quantum_Safe_Payload_2026"
echo "$TEST_STR" > "$VAULT_DIR/secret.txt"

# 5. Verify transparent read
READ_BACK=$(cat "$VAULT_DIR/secret.txt")
if [ "$READ_BACK" == "$TEST_STR" ]; then
    echo "[PASS] Transparent Read & Decryption Verified!"
else
    echo "[FAIL] Read back plaintext mismatch!"
    exit 1
fi

# 6. Verify signature file created
if [ -f "$BACKING_DIR/secret.txt.sig" ]; then
    echo "[PASS] CRYSTALS-Dilithium Digital Signature Generated!"
else
    echo "[FAIL] Signature file missing on disk!"
    exit 1
fi

# 7. Tamper test: modify ciphertext directly on backing disk
echo "HACKED_DATA" >> "$BACKING_DIR/secret.txt"
if cat "$VAULT_DIR/secret.txt" 2>/dev/null; then
    echo "[FAIL] Vault read tampered data without detecting corruption!"
    exit 1
else
    echo "[PASS] Tampering successfully detected! Dilithium blocked corrupted data."
fi

# 8. Teardown
fusermount3 -u "$VAULT_DIR"
kill -9 $VAULT_PID 2>/dev/null || true
echo "=== Week 3 All Tests Successfully Passed ==="
