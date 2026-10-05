#include "memory_guard.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void *secure_malloc(size_t size) {
    if (size == 0) return NULL;
    void *ptr = malloc(size);
    if (!ptr) return NULL;

    /* Lock memory in RAM to prevent disk swapping */
    if (mlock(ptr, size) != 0) {
        /* If unprivileged user exceeds RLIMIT_MEMLOCK, fallback safely */
    }
    return ptr;
}

void secure_zero(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    explicit_bzero(ptr, size);
}

void secure_free(void *ptr, size_t size) {
    if (!ptr) return;
    secure_zero(ptr, size);
    munlock(ptr, size);
    free(ptr);
}
