
#ifndef ALOCATOR_BLOCK_H
#define ALOCATOR_BLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include "alocator_impl.h"
#include "tree.h"

struct block_header {
    size_t size_curr;
    size_t size_prev;
    size_t offset;
    bool busy;
    bool first;
    bool last;
};

#define BLOCK_SIZE ROUND_BYTES(sizeof(struct block_header))
#define BLOCK_SIZE_MIN ROUND_BYTES(sizeof(tree_node_type))

struct block_header *block_split(struct block_header *block, size_t size);
void block_merge(struct block_header *block, struct block_header *block_right);
void block_clear(struct block_header *block);

static inline void *block_to_payload(const struct block_header *block)
{
    return (char *)block + BLOCK_SIZE;
}

static inline struct block_header *payload_to_block(const void *ptr)
{
    return (struct block_header *)((char *)ptr - BLOCK_SIZE);
}

static inline void *block_to_node(struct block_header *block)
{
    return block_to_payload(block);
}

static inline struct block_header *node_to_block( const tree_node_type *node)
{
    return payload_to_block(node);
}

static inline void init(struct block_header *block)
{
    block->busy = false;
    block->first = false;
    block->last = false;
}

static inline void set_busy_block(struct block_header *block)
{
    block->busy = true;
}

static inline void set_free_block(struct block_header *block)
{
    block->busy = false;
}

static inline bool is_busy(struct block_header *block)
{
    return block->busy;
}


static inline void set_curr_block_size(struct block_header *block, size_t size)
{
    block->size_curr = size;
}

static inline void set_prev_block_size(struct block_header *block, size_t size)
{
    block->size_prev = size;
}

static inline size_t get_curr_block_size(struct block_header *block)
{
    return block->size_curr;
}

static inline size_t get_prev_block_size(struct block_header *block)
{
    return block->size_prev;
}

static inline struct block_header *get_block_next(struct block_header *block)
{
    return (struct block_header *)
            ((char *)block + BLOCK_SIZE + get_curr_block_size(block));
}

static inline struct block_header *get_block_prev(struct block_header *const block)
{
    return (struct block_header *)
            ((char *)block - BLOCK_SIZE - get_prev_block_size(block));
}

static inline void arena_init(struct block_header *block, size_t size)
{
    block->first = true;
    block->last = true;
    block->busy = false;
    block->offset = 0;
    block->size_curr = size;
    block->size_prev = 0;
}

static inline void set_offset_block(struct block_header *block, size_t offset)
{
    block->offset = offset;
}

static inline size_t get_offset_block(const struct block_header *block)
{
    return block->offset;
}


#endif //ALOCATOR_BLOCK_H
