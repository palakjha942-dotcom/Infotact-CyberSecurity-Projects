#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

static char storage_path[PATH_MAX];
static uint8_t aes_key[32];
static uint8_t aes_iv[16];

static void init_pqc_engine() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "[-] Kyber512 initialization failed\n");
        exit(1);
    }
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key);
    OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key);

    memcpy(aes_key, shared_secret_dec, 32);
    RAND_bytes(aes_iv, 16);

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);
    OQS_KEM_free(kem);
    printf("[+] QuantumVault PQC Engine: Kyber-512 Handshake Complete\n");
    printf("[+] AES-256 Session Key Derived Transparently\n");
}

static void get_full_path(char fpath[PATH_MAX], const char *path) {
    snprintf(fpath, PATH_MAX, "%s%s", storage_path, path);
}

static int qv_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    char fpath[PATH_MAX];
    get_full_path(fpath, path);

    int res = lstat(fpath, stbuf);
    if (res == -1) return -errno;
    return 0;
}

static int qv_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;
    char fpath[PATH_MAX];
    get_full_path(fpath, path);

    DIR *dp = opendir(fpath);
    if (dp == NULL) return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0)) break;
    }
    closedir(dp);
    return 0;
}

static int qv_open(const char *path, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    get_full_path(fpath, path);

    int fd = open(fpath, fi->flags);
    if (fd == -1) return -errno;
    close(fd);
    return 0;
}

static int qv_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    (void) fi;
    char fpath[PATH_MAX];
    get_full_path(fpath, path);

    FILE *f = fopen(fpath, "rb");
    if (!f) return -errno;

    fseek(f, 0, SEEK_END);
    long enc_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (enc_len <= 0) {
        fclose(f);
        return 0;
    }

    unsigned char *enc_buf = malloc(enc_len);
    fread(enc_buf, 1, enc_len, f);
    fclose(f);

    unsigned char *dec_buf = malloc(enc_len + 16);
    int dec_len = 0, final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_DecryptUpdate(ctx, dec_buf, &dec_len, enc_buf, enc_len);
    EVP_DecryptFinal_ex(ctx, dec_buf + dec_len, &final_len);
    dec_len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    free(enc_buf);

    if (offset < dec_len) {
        if (offset + size > (size_t)dec_len) size = dec_len - offset;
        memcpy(buf, dec_buf + offset, size);
    } else {
        size = 0;
    }

    free(dec_buf);
    return size;
}

static int qv_write(const char *path, const char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    (void) fi;
    (void) offset;
    char fpath[PATH_MAX];
    get_full_path(fpath, path);

    unsigned char *enc_buf = malloc(size + 32);
    int enc_len = 0, final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
    EVP_EncryptUpdate(ctx, enc_buf, &enc_len, (const unsigned char *)buf, size);
    EVP_EncryptFinal_ex(ctx, enc_buf + enc_len, &final_len);
    enc_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    FILE *f = fopen(fpath, "wb");
    if (!f) {
        free(enc_buf);
        return -errno;
    }
    fwrite(enc_buf, 1, enc_len, f);
    fclose(f);
    free(enc_buf);

    return size;
}

static int qv_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    get_full_path(fpath, path);

    int fd = open(fpath, fi->flags, mode);
    if (fd == -1) return -errno;
    close(fd);
    return 0;
}

static int qv_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void) fi;
    char fpath[PATH_MAX];
    get_full_path(fpath, path);
    int res = truncate(fpath, size);
    if (res == -1) return -errno;
    return 0;
}

static const struct fuse_operations qv_oper = {
    .getattr  = qv_getattr,
    .readdir  = qv_readdir,
    .open     = qv_open,
    .read     = qv_read,
    .write    = qv_write,
    .create   = qv_create,
    .truncate = qv_truncate,
};

int main(int argc, char *argv[]) {
    if (!realpath("vault_storage", storage_path)) {
        perror("[-] Failed to resolve vault_storage");
        return 1;
    }
    init_pqc_engine();
    return fuse_main(argc, argv, &qv_oper, NULL);
}
