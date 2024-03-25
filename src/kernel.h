
#ifndef ALOCATOR_KERNEL_H
#define ALOCATOR_KERNEL_H

#include <stddef.h>

void *kmalloc(size_t size);
void kfree(void *ptr, size_t size);
void kreset(void *, size_t);
#endif //ALOCATOR_KERNEL_H
