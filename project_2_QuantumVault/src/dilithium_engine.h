#ifndef DILITHIUM_ENGINE_H
#define DILITHIUM_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#define DILITHIUM_ALG_NAME "ML-DSA-44"

int dilithium_init_keys(const char *key_dir);
int dilithium_sign_buffer(const uint8_t *data, size_t data_len, uint8_t **sig_out, size_t *sig_len_out);
int dilithium_verify_buffer(const uint8_t *data, size_t data_len, const uint8_t *sig, size_t sig_len);

#endif
