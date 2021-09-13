#include <stddef.h>

#include "tosaithe-util.h"

/*
void debug_write(void *p)
{
    con_write((uint64_t)p);
}

void debug_write(const char16_t *msg)
{
    con_write((CHAR16 *)msg);
}
*/

extern "C"
void abort(void) {
    con_write(L"** Aborted! **\r\n");
    while (true) {
        asm volatile ("hlt\n");
    }
}

extern "C"
void *malloc(size_t size) {
    return alloc_pool(size);
}

extern "C"
void free(void *v) {
    return free_pool(v);
}
