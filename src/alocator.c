#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <memory.h>

#include "block.h"
#include "kernel.h"
#include "alocator.h"
#include "config.h"

static tree_type blocks_tree = TREE_INIT

static struct block_header *arena_alloc(void) {
    struct block_header *block;
    block = kmalloc(ARENA_SIZE);
    if (block != NULL) {
        arena_init(block, ARENA_SIZE - BLOCK_SIZE);
    }
    return block;
}

static void tree_add_block(struct block_header *block) {
    assert(is_busy(block) == false);
    tree_add(&blocks_tree, block_to_node(block), get_curr_block_size(block));
}

static void tree_remove_block(struct block_header *block) {
    assert(is_busy(block) == false);
    tree_remove(&blocks_tree, block_to_node(block));
}

void *mem_alloc(size_t size) {
    struct block_header *block, *split_block;

    tree_node_type *node;

    if (size > BLOCK_SIZE_MAX)
        return NULL;
    if (size < BLOCK_SIZE_MIN)
        size = BLOCK_SIZE_MIN;

    size = ROUND_BYTES(size);

    node = tree_find_best(&blocks_tree, size);
    if (node == NULL) {
        block = arena_alloc();
        if (block == NULL)
            return NULL;
    } else {
        tree_remove(&blocks_tree, node);
        block = node_to_block(node);
    }
    split_block = block_split(block, size);
    if (split_block != NULL){
        tree_add_block(split_block);
    }
    return block_to_payload(block);
}

void mem_free(void *ptr) {

    struct block_header *block, *r_block, *l_block;

    if (ptr == NULL)
        return;

    block = payload_to_block(ptr);
    set_free_block(block);

    if (!(block->last)){
        r_block = get_block_next(block);
        if (!is_busy(r_block)){
            tree_remove_block(r_block);
            block_merge(block, r_block);
        }
    }
    if (!(block->first)){
        l_block = get_block_prev(block);
        if (!is_busy(l_block)){
            tree_remove_block(l_block);
            block_merge(l_block, block);
            block = l_block;
        }
    }
    if (block->first && block->last){
        kfree(block, ARENA_SIZE);
    } else {
        block_clear(block);
        tree_add_block(block);
    }
}

void *mem_realloc(void *ptr, size_t size) {
    struct block_header *block_curr;
    void *new_ptr;
    size_t size_curr;

    if (size > BLOCK_SIZE_MAX)
        return NULL;
    if (size < BLOCK_SIZE_MIN)
        size = BLOCK_SIZE_MIN;
    size = ROUND_BYTES(size);

    if (ptr == NULL)
        return mem_alloc(size);


    block_curr = payload_to_block(ptr);
    size_curr = get_curr_block_size(block_curr);
    if (size_curr == size)
        return ptr;

    if (size < size_curr)
        return NULL;

    new_ptr = mem_alloc(size);

    if (new_ptr != NULL) {
        memcpy(new_ptr, ptr, size_curr);
        mem_free(ptr);
    }
    return new_ptr;
}

static void show_node(const tree_node_type *node, const bool linked){
    struct block_header *block = node_to_block(node);

    printf("[%20p] %20zu %20zu %s%s%s%s\n",
           (void *)block,
           get_curr_block_size(block), get_prev_block_size(block),
           is_busy(block) ? "busy" : "free",
           block->first ? " first " : "",
           block->last ? " last" : "",
           linked ? " linked" : "");
}

void mem_show(const char *msg) {
    printf("%s:\n", msg);
    if (tree_is_empty(&blocks_tree))
        printf("Tree is empty");
    else
        tree_walk(&blocks_tree, show_node);
}
