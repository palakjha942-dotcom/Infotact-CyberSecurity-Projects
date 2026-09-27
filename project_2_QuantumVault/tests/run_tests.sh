#!/bin/bash
# ==============================================================================
# QuantumVault: Automated Test & Validation Pipeline
# ==============================================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "=========================================="
echo " Starting QuantumVault Validation Tests   "
echo "=========================================="

# 1. Compile Kyber Test Binary
echo -n "[TEST 1] Compiling Kyber-512 PQC Test Harness... "
gcc -O2 src/test_kyber.c -o tests/test_kyber -loqs -loqs -lcrypto
if [ $? -eq 0 ]; then
    echo -e "${GREEN}SUCCESS${NC}"
else
    echo -e "${RED}FAILED${NC}"
    exit 1
fi

# 2. Execute Kyber Test
echo "[TEST 2] Running Kyber-512 Key Encapsulation Mechanism (KEM)..."
./tests/test_kyber
if [ $? -eq 0 ]; then
    echo -e "[TEST 2] ${GREEN}PASSED: Shared Secret Derived Successfully${NC}"
else
    echo -e "[TEST 2] ${RED}FAILED: Kyber Test Errored${NC}"
    exit 1
fi

# 3. Compile QuantumVault FUSE Filesystem
echo -n "[TEST 3] Compiling QuantumVault FUSE Filesystem Target... "
gcc -Wall -O2 `pkg-config fuse3 --cflags` src/quantum_vault.c `pkg-config fuse3 --libs` -loqs -lcrypto -o tests/quantum_vault
if [ $? -eq 0 ]; then
    echo -e "${GREEN}SUCCESS${NC}"
else
    echo -e "${RED}FAILED${NC}"
    exit 1
fi

echo "=========================================="
echo -e "${GREEN}All Build & Primitive Security Checks PASSED!${NC}"
echo "=========================================="
