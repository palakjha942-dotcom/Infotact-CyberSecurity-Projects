#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stddef.h>

#define KDF_SALT_SIZE 16
#define KDF_KEY_SIZE 32
#define KDF_ITERATIONS 100000

/* Derive a secure encryption key from user password using PBKDF2 */
int derive_master_key(const char *password, size_t pass_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *out_key, size_t key_len);

#endif /* KEY_DERIVATION_H */
