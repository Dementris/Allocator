#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "src/alocator.h"
#include "src/tester.h"

static void *buf_alloc(size_t size)
{
    char *buf;
    size_t i;

    buf = mem_alloc(size);
    if (buf != NULL)
        for (i = 0; i < size; ++i)
            buf[i] = (char)rand();
    return buf;
}

int main() {
    tester(true);
}
