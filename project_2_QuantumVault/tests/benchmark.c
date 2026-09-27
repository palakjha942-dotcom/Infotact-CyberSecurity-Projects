#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define ITERATIONS 1000

static double get_time_diff_us(struct timespec start, struct timespec end) {
    return ((end.tv_sec - start.tv_sec) * 1e6) + ((end.tv_nsec - start.tv_nsec) / 1e3);
}

int main(void) {
    struct timespec start, end;
    printf("=====================================================\n");
    printf("  QuantumVault: Security Primitive Benchmarks (%d iters)\n", ITERATIONS);
    printf("=====================================================\n");

    /* 1. Kyber-512 KEM Benchmark */
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to load Kyber-512 engine.\n");
        return 1;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        OQS_KEM_keypair(kem, public_key, secret_key);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("[KYBER-512] Keypair Generation Latency: %.2f us/op\n", get_time_diff_us(start, end) / ITERATIONS);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("[KYBER-512] Encapsulation Latency:     %.2f us/op\n", get_time_diff_us(start, end) / ITERATIONS);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("[KYBER-512] Decapsulation Latency:     %.2f us/op\n", get_time_diff_us(start, end) / ITERATIONS);

    OQS_MEM_cleanse(secret_key, kem->length_secret_key);
    OQS_MEM_cleanse(shared_secret, kem->length_shared_secret);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret);
    OQS_KEM_free(kem);

    /* 2. AES-256-GCM Encryption Benchmark (4KB blocks) */
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char plaintext[4096];
    unsigned char out_ciphertext[4096];
    unsigned char tag[16];
    int outlen;

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    memset(plaintext, 'A', sizeof(plaintext));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, out_ciphertext, &outlen, plaintext, sizeof(plaintext));
        EVP_EncryptFinal_ex(ctx, out_ciphertext + outlen, &outlen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("[AES-256-GCM] 4KB Block Encrypt Latency: %.2f us/op\n", get_time_diff_us(start, end) / ITERATIONS);

    EVP_CIPHER_CTX_free(ctx);
    printf("=====================================================\n");
    return 0;
}
