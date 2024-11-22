
#ifndef ALLOCATOR_INTERNAL_H
#define ALLOCATOR_INTERNAL_H

#include <stddef.h>

void preallocate_heap();
struct block_meta *map_new_area(size_t size);
void split_block(struct block_meta *block, size_t size);
void coalesce_blocks(struct block_meta *block);
void coalesce_blocks_to_the_right(struct block_meta *block, struct block_meta *next_block);
struct block_meta *find_best_block(size_t size);
struct block_meta *add_new_block(size_t size);
void expand_block(size_t size, struct block_meta *last);

#endif