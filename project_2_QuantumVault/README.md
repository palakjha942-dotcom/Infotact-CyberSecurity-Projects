# QuantumVault: Post-Quantum Encrypted Virtual Filesystem

## Week 1: PQC Cryptographic Engine
- Integrated `liboqs` for Post-Quantum Cryptography.
- Implemented and verified Kyber-512 Key Encapsulation Mechanism (KEM).
- Cryptographic verification via `src/test_kyber.c`.

## Week 2: FUSE Transparent Storage Pipeline
- Built Userspace Virtual Filesystem driver with `fuse3`.
- Symmetric session key derivation via Kyber-512 shared secret.
- Implemented transparent AES-256-CBC file read/write pipeline:
  - Plaintext virtual access on mount point (`vault_mount`).
  - Raw encrypted ciphertext storage on disk (`vault_storage`).

## Build & Verification

```bash
# Build all components
make all

# Run automated post-quantum primitives validation suite
make test

# Run micro-benchmarks
gcc -O2 tests/benchmark.c -o tests/benchmark -loqs -lcrypto
./tests/benchmark

```


## Performance Benchmarks (Empirical Latency)

| Security Primitive | Operation | Measured Latency |
| :--- | :--- | :--- |
| **Kyber-512 (ML-KEM)** | Keypair Generation | ~31.49 µs/op |
| **Kyber-512 (ML-KEM)** | Encapsulation | ~37.36 µs/op |
| **Kyber-512 (ML-KEM)** | Decapsulation | ~33.22 µs/op |
| **AES-256-GCM** | 4KB Block Encryption | ~4.35 µs/op |
