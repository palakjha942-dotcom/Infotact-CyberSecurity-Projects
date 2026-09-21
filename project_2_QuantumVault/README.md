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
