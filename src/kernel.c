#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <memoryapi.h>

#include "kernel.h"


#define DEBUG_KERNEL_RESET

static _Noreturn void failed_kmalloc(void){
#define msg "kmalloc() failed\n"
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
#undef msg
    exit(EXIT_FAILURE);
}

static _Noreturn void failed_kfree(void){
#define msg "kfree() failed\n"
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
#undef msg
    exit(EXIT_FAILURE);
}

static _Noreturn void failed_kreset(void)
{
#define msg "kreset() failed\n"
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
#undef msg
    exit(EXIT_FAILURE);
}

void *kmalloc(size_t size) {
    void *ptr;

    ptr = VirtualAlloc(NULL, size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (ptr == NULL) {
        // Check error code and call failed_kernel_alloc() if necessarily.
        // failed_kernel_alloc();
        return NULL;
    }
    return ptr;
}

void kfree(void *ptr, size_t size) {
    (void) size;
    if (VirtualFree(ptr, 0, MEM_RELEASE) == 0)
        failed_kfree();
}

void kreset(void *ptr, size_t size){
#ifdef DEBUG_KERNEL_RESET
    memset(ptr, 0x7e, size);
#endif
    if (VirtualAlloc(ptr, size, MEM_RESET, PAGE_READWRITE) == NULL)
        failed_kreset();
}
