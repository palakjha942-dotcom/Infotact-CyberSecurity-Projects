#ifndef MEMORY_GUARD_H
#define MEMORY_GUARD_H

#include <stddef.h>

/* Allocate memory locked into RAM (prevents paging/swap to disk) */
void *secure_malloc(size_t size);

/* Securely wipe buffer using compiler-barrier zeroization */
void secure_zero(void *ptr, size_t size);

/* Unlock and free secure memory */
void secure_free(void *ptr, size_t size);

#endif /* MEMORY_GUARD_H */
