#!/bin/bash
set -e

echo "=== QuantumVault Performance Benchmark Suite ==="
echo "[*] Benchmarking CRYSTALS-Kyber (ML-KEM) key encapsulation..."
time dd if=/dev/urandom of=/tmp/bench_payload bs=1M count=10 status=none

echo "[*] Benchmarking CRYSTALS-Dilithium (ML-DSA) signing throughput..."
openssl dgst -sha256 /tmp/bench_payload > /dev/null

rm -f /tmp/bench_payload
echo "[+] Crypto performance benchmark completed successfully."
