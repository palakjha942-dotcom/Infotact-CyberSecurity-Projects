#include "key_derivation.h"
#include <openssl/evp.h>
#include <string.h>

int derive_master_key(const char *password, size_t pass_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *out_key, size_t key_len) {
    if (!password || !salt || !out_key || key_len == 0) return -1;

    int ret = PKCS5_PBKDF2_HMAC(password, (int)pass_len,
                                salt, (int)salt_len,
                                KDF_ITERATIONS,
                                EVP_sha256(),
                                (int)key_len,
                                out_key);
    return (ret == 1) ? 0 : -1;
}
