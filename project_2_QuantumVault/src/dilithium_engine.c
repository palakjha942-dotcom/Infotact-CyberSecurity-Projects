#define _GNU_SOURCE
#include "dilithium_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

static uint8_t *g_public_key = NULL;
static uint8_t *g_secret_key = NULL;
static size_t g_pubkey_len = 0;
static size_t g_seckey_len = 0;

int dilithium_init_keys(const char *key_dir) {
    (void)key_dir;
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_44)) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) return -1;

    g_pubkey_len = sig->length_public_key;
    g_seckey_len = sig->length_secret_key;

    g_public_key = (uint8_t *)malloc(g_pubkey_len);
    g_secret_key = (uint8_t *)malloc(g_seckey_len);

    if (!g_public_key || !g_secret_key) {
        OQS_SIG_free(sig);
        return -1;
    }

    if (OQS_SIG_keypair(sig, g_public_key, g_secret_key) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return -1;
    }

    OQS_SIG_free(sig);
    return 0;
}

int dilithium_sign_buffer(const uint8_t *data, size_t data_len, uint8_t **sig_out, size_t *sig_len_out) {
    if (!g_secret_key) return -1;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) return -1;

    *sig_out = (uint8_t *)malloc(sig->length_signature);
    if (!*sig_out) {
        OQS_SIG_free(sig);
        return -1;
    }

    if (OQS_SIG_sign(sig, *sig_out, sig_len_out, data, data_len, g_secret_key) != OQS_SUCCESS) {
        free(*sig_out);
        *sig_out = NULL;
        OQS_SIG_free(sig);
        return -1;
    }

    OQS_SIG_free(sig);
    return 0;
}

int dilithium_verify_buffer(const uint8_t *data, size_t data_len, const uint8_t *sig_buf, size_t sig_len) {
    if (!g_public_key || !sig_buf) return -1;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) return -1;

    OQS_STATUS status = OQS_SIG_verify(sig, data, data_len, sig_buf, sig_len, g_public_key);
    OQS_SIG_free(sig);

    return (status == OQS_SUCCESS) ? 0 : -1;
}
