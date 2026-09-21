#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    printf("[*] Initializing QuantumVault PQC Engine...\n");

    const char *method_name = OQS_KEM_alg_kyber_512;
    if (!OQS_KEM_alg_is_enabled(method_name)) {
        // Fallback to ML-KEM-512 if Kyber is standardized under new name
        method_name = OQS_KEM_alg_ml_kem_512;
        if (!OQS_KEM_alg_is_enabled(method_name)) {
            fprintf(stderr, "[-] Algorithm not enabled in liboqs.\n");
            return 1;
        }
    }

    OQS_KEM *kem = OQS_KEM_new(method_name);
    if (kem == NULL) {
        fprintf(stderr, "[-] Failed to initialize KEM.\n");
        return 1;
    }

    printf("[+] Algorithm Loaded: %s\n", kem->method_name);

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    // 1. Generate Keypair
    printf("[*] Generating Post-Quantum Keypair...\n");
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[-] Keypair generation failed.\n");
        return 1;
    }
    printf("[+] Public Key Generated (%zu bytes)\n", kem->length_public_key);
    printf("[+] Secret Key Generated (%zu bytes)\n", kem->length_secret_key);

    // 2. Encapsulation (Encryption)
    printf("[*] Encapsulating shared secret (Simulating file encryption key lock)...\n");
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[-] Encapsulation failed.\n");
        return 1;
    }
    printf("[+] Ciphertext generated (%zu bytes)\n", kem->length_ciphertext);

    // 3. Decapsulation (Decryption)
    printf("[*] Decapsulating shared secret (Unlocking secret with private key)...\n");
    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[-] Decapsulation failed.\n");
        return 1;
    }

    // 4. Verify match
    if (memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0) {
        printf("[SUCCESS] Post-Quantum shared secret matched perfectly!\n");
        printf("[SUCCESS] QuantumVault Week 1 C Crypto verification passed.\n");
    } else {
        printf("[-] Shared secrets do not match!\n");
    }

    // Cleanup
    OQS_MEM_cleanse(secret_key, kem->length_secret_key);
    OQS_MEM_cleanse(shared_secret_enc, kem->length_shared_secret);
    OQS_MEM_cleanse(shared_secret_dec, kem->length_shared_secret);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);

    return 0;
}
