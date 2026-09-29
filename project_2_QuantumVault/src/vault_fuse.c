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
static unsigned char g_vault_key[32] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                                        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
                                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
static unsigned char g_vault_iv[16]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

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

    struct stat st;
    if (stat(full_path, &st) == -1) {
        return -errno;
    }

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = st.st_size;
    return 0;
}

static int vault_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void)path; (void)offset; (void)fi; (void)flags;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    return 0;
}

static int vault_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode; (void)fi;
    char full_path[512];
    get_backing_path(full_path, path);

    int fd = open(full_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) return -errno;
    close(fd);
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

    /* 1. Transparent AES-256 Encryption */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[size + 64];
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_vault_key, g_vault_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)buf, size);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    /* 2. Dilithium (ML-DSA-44) Sign ciphertext */
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    dilithium_sign_buffer(ciphertext, ciphertext_len, &sig, &sig_len);

    /* 3. Write ciphertext to backing disk */
    FILE *fp = fopen(full_path, "wb");
    if (!fp) return -errno;
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);

    /* 4. Write signature to backing disk */
    char sig_path[520];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", full_path);
    FILE *sig_fp = fopen(sig_path, "wb");
    if (sig_fp && sig) {
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

    FILE *fp = fopen(full_path, "rb");
    if (!fp) return -errno;
    fseek(fp, 0, SEEK_END);
    long cipher_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (cipher_len <= 0) {
        fclose(fp);
        return 0;
    }

    unsigned char *ciphertext = malloc(cipher_len);
    fread(ciphertext, 1, cipher_len, fp);
    fclose(fp);

    /* 1. Verify Dilithium Signature */
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
            return -EIO;
        }
        free(sig_buf);
    }

    /* 2. Transparent Decryption */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0;
    unsigned char *plaintext = malloc(cipher_len + 32);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_vault_key, g_vault_iv);
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -EIO;
    }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -EIO;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    size_t to_copy = (size < (size_t)plaintext_len) ? size : (size_t)plaintext_len;
    memcpy(buf, plaintext, to_copy);

    free(ciphertext);
    free(plaintext);
    return to_copy;
}

static const struct fuse_operations vault_oper = {
    .getattr = vault_getattr,
    .readdir = vault_readdir,
    .create  = vault_create,
    .open    = vault_open,
    .read    = vault_read,
    .write   = vault_write,
};

int main(int argc, char *argv[]) {
    mkdir(g_backing_dir, 0700);
    dilithium_init_keys(NULL);
    return fuse_main(argc, argv, &vault_oper, NULL);
}
