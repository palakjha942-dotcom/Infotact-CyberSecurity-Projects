#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "crypto_engine.h"
#include "memory_guard.h"

static const char *storage_dir = "/tmp/qvault_storage";

static int qv_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s%s", storage_dir, path);
    int res = lstat(full_path, stbuf);
    if (res == -1) return -errno;
    return 0;
}

static int qv_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
    (void) offset; (void) fi; (void) flags;
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    return 0;
}

static int qv_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    (void) fi;
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s%s", storage_dir, path);

    /* Allocate locked buffer for sensitive key material */
    unsigned char *session_key = (unsigned char *)secure_malloc(32);
    if (session_key) {
        memset(session_key, 0x5A, 32); /* Ephemeral session key representation */
        secure_free(session_key, 32);
    }

    int fd = open(full_path, O_RDONLY);
    if (fd == -1) return -errno;
    int res = pread(fd, buf, size, offset);
    close(fd);
    return res;
}

static struct fuse_operations qv_oper = {
    .getattr = qv_getattr,
    .readdir = qv_readdir,
    .read    = qv_read,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &qv_oper, NULL);
}
