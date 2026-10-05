#ifndef MEMORY_GUARD_H
#define MEMORY_GUARD_H

#include <stddef.h>

/* Allocate locked, non-dumpable memory in RAM */
void *secure_malloc(size_t size);

/* Compiler barrier zeroization */
void secure_zero(void *ptr, size_t size);

/* Unlock, wipe and free secure buffer */
void secure_free(void *ptr, size_t size);

/* Disable core dump creation for sensitive memory areas */
int protect_buffer_dumps(void *ptr, size_t size);

#endif /* MEMORY_GUARD_H */
