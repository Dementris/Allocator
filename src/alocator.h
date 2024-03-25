
#ifndef ALOCATOR_ALOCATOR_H
#define ALOCATOR_ALOCATOR_H

#include "config.h"

#define ARENA_SIZE (ALLOCATOR_ARENA_PAGES * ALLOCATOR_PAGE_SIZE)
#define BLOCK_SIZE_MAX (ARENA_SIZE - BLOCK_SIZE)

void *mem_alloc(size_t size);
void mem_free(void *payload);
void mem_show(const char *msg);
void * mem_realloc(void *ptr1, size_t size);

#endif //ALOCATOR_ALOCATOR_H
