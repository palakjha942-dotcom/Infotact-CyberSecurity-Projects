#include "memory_guard.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int protect_buffer_dumps(void *ptr, size_t size) {
    if (!ptr || size == 0) return -1;
#ifdef MADV_DONTDUMP
    return madvise(ptr, size, MADV_DONTDUMP);
#else
    return 0;
#endif
}

void *secure_malloc(size_t size) {
    if (size == 0) return NULL;
    void *ptr = malloc(size);
    if (!ptr) return NULL;

    /* Lock memory in RAM to prevent disk swapping */
    mlock(ptr, size);

    /* Prevent inclusion in crash core dumps */
    protect_buffer_dumps(ptr, size);

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
