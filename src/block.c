#include <stdlib.h>
#include <assert.h>
#include "block.h"
#include "config.h"
#include "kernel.h"

struct block_header *block_split(struct block_header *block, size_t size) {

    assert(get_curr_block_size(block) >= size);

    struct block_header *block_right;
    size_t size_rest;

    set_busy_block(block);
    size_rest = get_curr_block_size(block) - size;
    if (size_rest >= BLOCK_SIZE + BLOCK_SIZE_MIN) {
        size_rest -= BLOCK_SIZE;
        set_curr_block_size(block, size);
        block_right = get_block_next(block);
        init(block_right);
        set_curr_block_size(block_right, size_rest);
        set_prev_block_size(block_right, size);
        set_offset_block(block_right, get_offset_block(block) + size + BLOCK_SIZE);
        if (block->last){
            block->last = false;
            block_right->last = true;
        } else {
            set_prev_block_size(get_block_next(block_right), size_rest);
        }
        return block_right;

    }
    return NULL;

}

void block_merge(struct block_header *block, struct block_header *block_right) {
    assert(block_right->busy == false);
    assert(get_block_next(block) == block_right);

    size_t size;

    size = get_curr_block_size(block) + get_curr_block_size(block_right) + BLOCK_SIZE;
    set_curr_block_size(block, size);
    if (block_right->last)
        block->last = true;
    else
        set_prev_block_size(get_block_next(block_right), size);
}

void block_clear(struct block_header *block){
    size_t offset, offset1, offset2;

    size_t size_curr = get_curr_block_size(block);

    if (size_curr - sizeof(tree_node_type) < ALLOCATOR_PAGE_SIZE)
        return;

    offset = get_offset_block(block);
    offset1 = offset + BLOCK_SIZE + sizeof(tree_node_type);
    offset1 = (offset1 + ALLOCATOR_PAGE_SIZE - 1) &
            ~((size_t)ALLOCATOR_PAGE_SIZE - 1);
    offset2 = offset + size_curr + BLOCK_SIZE;
    offset2 &= ~((size_t)ALLOCATOR_PAGE_SIZE - 1);
    if (offset1 == offset2)
        return;

    assert(((offset2 - offset1) & ((size_t)ALLOCATOR_PAGE_SIZE - 1)) == 0);

    kreset((char *)block + (offset1 - offset), offset2 - offset1);
}
