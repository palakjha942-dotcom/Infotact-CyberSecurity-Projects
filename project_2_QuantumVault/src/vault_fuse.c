#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "dilithium_engine.h"

static char g_backing_dir[512] = "/tmp/quantum_vault_backing";
static unsigned char g_vault_key[32] = {0xAA};
static unsigned char g_vault_iv[16]  = {0x55};

static void get_backing_path(char *dest, const char *path) {
    snprintf(dest, 512, "%s%s", g_backing_dir, path);
}

static int vault_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char full_path[512];
    get_backing_path(full_path, path);

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    if (stat(full_path, stbuf) == -1) {
        return -errno;
    }
    return 0;
}

static int vault_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    return 0;
}

static int vault_open(const char *path, struct fuse_file_info *fi) {
    (void)path; (void)fi;
    return 0;
}

static int vault_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
    (void)offset; (void)fi;
    char full_path[512];
    get_backing_path(full_path, path);

    /* 1. Transparent Encryption (AES-256-CBC) */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[size + 32];
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_vault_key, g_vault_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)buf, size);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    /* 2. Dilithium Digital Signature */
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    dilithium_sign_buffer(ciphertext, ciphertext_len, &sig, &sig_len);

    /* 3. Persist to Backing Storage */
    FILE *fp = fopen(full_path, "wb");
    if (!fp) return -errno;
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);

    /* Store detached signature */
    char sig_path[520];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", full_path);
    FILE *sig_fp = fopen(sig_path, "wb");
    if (sig_fp) {
        fwrite(sig, 1, sig_len, sig_fp);
        fclose(sig_fp);
    }
    if (sig) free(sig);

    return size;
}

static int vault_read(const char *path, char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
    (void)offset; (void)fi;
    char full_path[512];
    char sig_path[520];
    get_backing_path(full_path, path);
    snprintf(sig_path, sizeof(sig_path), "%s.sig", full_path);

    /* Read encrypted ciphertext */
    FILE *fp = fopen(full_path, "rb");
    if (!fp) return -errno;
    fseek(fp, 0, SEEK_END);
    long cipher_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *ciphertext = malloc(cipher_len);
    fread(ciphertext, 1, cipher_len, fp);
    fclose(fp);

    /* Verify Dilithium Signature */
    FILE *sig_fp = fopen(sig_path, "rb");
    if (sig_fp) {
        fseek(sig_fp, 0, SEEK_END);
        long sig_len = ftell(sig_fp);
        fseek(sig_fp, 0, SEEK_SET);

        uint8_t *sig_buf = malloc(sig_len);
        fread(sig_buf, 1, sig_len, sig_fp);
        fclose(sig_fp);

        if (dilithium_verify_buffer(ciphertext, cipher_len, sig_buf, sig_len) != 0) {
            free(sig_buf);
            free(ciphertext);
            printf("[SECURITY ALERT] Dilithium Signature Mismatch! File has been tampered.\n");
            return -EIO;
        }
        free(sig_buf);
    }

    /* Transparent Decryption (AES-256-CBC) */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0;
    unsigned char *plaintext = malloc(cipher_len + 32);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_vault_key, g_vault_iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    size_t bytes_to_copy = (size < (size_t)plaintext_len) ? size : (size_t)plaintext_len;
    memcpy(buf, plaintext, bytes_to_copy);

    free(ciphertext);
    free(plaintext);
    return bytes_to_copy;
}

static const struct fuse_operations vault_oper = {
    .getattr = vault_getattr,
    .readdir = vault_readdir,
    .open    = vault_open,
    .read    = vault_read,
    .write   = vault_write,
};

int main(int argc, char *argv[]) {
    mkdir(g_backing_dir, 0700);
    dilithium_init_keys(NULL);
    return fuse_main(argc, argv, &vault_oper, NULL);
}
