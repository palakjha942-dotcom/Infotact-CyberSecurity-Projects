#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/memory_guard.h"

int main(void) {
    printf("[*] Testing secure memory allocation and zeroization...\n");
    
    size_t test_size = 64;
    char *secret_buffer = (char *)secure_malloc(test_size);
    assert(secret_buffer != NULL);
    
    /* Populate with sensitive data */
    memset(secret_buffer, 0xAA, test_size);
    assert((unsigned char)secret_buffer[0] == 0xAA);
    
    /* Securely wipe */
    secure_zero(secret_buffer, test_size);
    assert(secret_buffer[0] == 0);
    assert(secret_buffer[test_size - 1] == 0);
    
    /* Release and unlock */
    secure_free(secret_buffer, test_size);
    
    printf("[+] Memory guard unit tests passed successfully!\n");
    return 0;
}
