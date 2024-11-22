// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "utils/osmem.h"
#include "utils/block_meta.h"



#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define META_SIZE ALIGN(sizeof(struct block_meta))
#define MMAP_THRESHOLD (128 * 1024)
#define MINEU(a, b) ((a) < (b) ? (a) : (b))

struct block_meta *head;
int prealloc;

void preallocate_heap(void)
{
	// i will preallocate 128 kiB using sbrk
	void *preallocated_memory = sbrk(MMAP_THRESHOLD);

	DIE(preallocated_memory == (void *)-1, "sbrk");
	head = (struct block_meta *)preallocated_memory;
	head->size = MMAP_THRESHOLD - META_SIZE;
	head->status = STATUS_FREE;
	head->next = NULL;
	head->prev = NULL;
	prealloc = 1;
}

void split_block(struct block_meta *block, size_t size)
{
	size = ALIGN(size);
	// poate mai pun un if
	// if the block i am currently in has the space required for my block and an
	// extra block and one byte of memory
	if (block->size >= size + META_SIZE + ALIGNMENT) {
		struct block_meta *new_block =
			(struct block_meta *)((char *)block + META_SIZE + size);
		new_block->size = block->size - META_SIZE - size;
		new_block->status = STATUS_FREE;
		new_block->prev = block;
		new_block->next = block->next;

		block->next = new_block;
		block->size = size;
		if (new_block->next)
			new_block->next->prev = new_block;
	}
}

// i will call coalesce every time i call the free function
void coalesce_blocks(struct block_meta *block)
{
	// coalesce to next block if possible
	if (block->next && block->next->status == STATUS_FREE) {
		block->size = block->size + META_SIZE + block->next->size;
		block->next = block->next->next;
		if (block->next)
			block->next->prev = block;
	}

	// coalesce the previous block if possible
	if (block->prev && block->prev->status == STATUS_FREE) {
		block->prev->size = block->prev->size + META_SIZE + block->size;
		block->prev->next = block->next;
		if (block->prev->next)
			block->prev->next->prev = block->prev;
	}
}

void coalesce_blocks_to_the_right(struct block_meta *block,
	struct block_meta *next_block)
{
	block->size += META_SIZE + next_block->size;
	block->next = next_block->next;
	if (next_block->next)
		next_block->next->prev = block;
}

struct block_meta *find_best_block(size_t size)
{
	size = ALIGN(size);
	struct block_meta *parcurg = head;
	struct block_meta *best_block = NULL;

	while (parcurg) {
		if (parcurg->size >= size && parcurg->status == STATUS_FREE) {
			if (best_block == NULL || parcurg->size < best_block->size)
				best_block = parcurg;
		}
		parcurg = parcurg->next;
	}
	return best_block;
}

struct block_meta *map_new_area(size_t size)
{
	void *request = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(request == MAP_FAILED, "mmap");

	struct block_meta *new_block = (struct block_meta *)request;

	new_block->status = STATUS_MAPPED;
	new_block->size = size;
	new_block->next = NULL;
	new_block->prev = NULL;
	return new_block;
}

struct block_meta *add_new_block(size_t size)
{
	size = ALIGN(size);

	struct block_meta *last = head;
	struct block_meta *new_block;
	void *request;

	while (last && last->next)
		last = last->next;

	request = sbrk(size + META_SIZE);
	DIE(request == (void *)-1, "sbrk");
	new_block = (struct block_meta *)request;
	new_block->status = STATUS_ALLOC;
	new_block->size = size;
	new_block->next = NULL;
	new_block->prev = last;

	if (last)
		last->next = new_block;
	else
		head = new_block;

	return new_block;
}

void expand_block(size_t size, struct block_meta *last)
{
	size = ALIGN(size);

	size_t add_size = size - last->size;
	void *request = sbrk(add_size);

	DIE(request == (void *)-1, "sbrk");

	last->status = STATUS_ALLOC;
	last->size = size;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	size = ALIGN(size);

	if (size == 0)
		return NULL;

	// preallocate heap
	if (prealloc == 0 && size + META_SIZE < MMAP_THRESHOLD)
		preallocate_heap();

	if (size + META_SIZE >= MMAP_THRESHOLD) {
		struct block_meta *new_block = map_new_area(size);

		return (char *)new_block + META_SIZE;
	}

	struct block_meta *last = head;

	while (last && last->next)
		last = last->next;

	struct block_meta *block = find_best_block(size);

	if (block) {
		split_block(block, size);
		block->status = STATUS_ALLOC;
	} else if (last && last->status == STATUS_FREE) {
		expand_block(size, last);
		return (char *)last + META_SIZE;
	} else if (size < MMAP_THRESHOLD) {
		block = add_new_block(size);
	} else {
		block = map_new_area(size);
	}
	return (char *)block + META_SIZE;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *block = (struct block_meta *)((char *)ptr - META_SIZE);

	// poate mai trebuie sa verific daca memoria depaseste 128 kiB
	if (block->status == STATUS_FREE) {
		return;
	} else if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce_blocks(block);
	} else if (block->status == STATUS_MAPPED) {
		munmap(block, block->size + META_SIZE);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	size_t total_size = ALIGN(nmemb * size);

	if (size == 0 || nmemb == 0)
		return NULL;

	if (prealloc == 0 && total_size + META_SIZE < 4096)
		preallocate_heap();

	if (total_size + META_SIZE >= 4096) {
		struct block_meta *new_block = map_new_area(total_size);

		memset((char *)new_block + META_SIZE, 0, total_size);
		return (char *)new_block + META_SIZE;
	}

	struct block_meta *last = head;

	while (last && last->next)
		last = last->next;

	struct block_meta *block = find_best_block(total_size);

	if (block) {
		split_block(block, total_size);
		block->status = STATUS_ALLOC;
	} else if (last && last->status == STATUS_FREE) {
		expand_block(total_size, last);
		memset((char *)last + META_SIZE, 0, total_size);
		return (char *)last + META_SIZE;
	} else if (size < 4096) {
		block = add_new_block(total_size);
	} else {
		block = map_new_area(total_size);
	}

	memset((char *)block + META_SIZE, 0, total_size);
	return (char *)block + META_SIZE;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = (struct block_meta *)((char *)ptr - META_SIZE);

	if (block->status == STATUS_FREE)
		return NULL;

	size = ALIGN(size);

	// If size exceeds MMAP_THRESHOLD, use mmap
	if (size > MMAP_THRESHOLD) {
		struct block_meta *new_block = map_new_area(size);

		memcpy((char *)new_block + META_SIZE, ptr, MINEU(block->size, size));
		os_free(ptr);
		return (char *)new_block + META_SIZE;
	}

	// If size is smaller, truncate the block and split if necessary
	if (block->size >= size && block->status != STATUS_MAPPED) {
		split_block(block, size);
		return ptr;
	}

	// Expand the last block if it is free
	struct block_meta *last = head;

	while (last && last->next)
		last = last->next;

	if (last == block && last->status == STATUS_ALLOC) {
		expand_block(size, last);
		memcpy((char *)last + META_SIZE, ptr, MINEU(size, last->size));
		return (char *)last + META_SIZE;
	}

	// Try to coalesce with neighboring blocks if expanding
	struct block_meta *next_block = block->next;

	while (next_block && next_block->status == STATUS_FREE && block->status != STATUS_MAPPED) {
		coalesce_blocks_to_the_right(block, next_block);
		if (block->size >= size) {
			split_block(block, size);
			return ptr;
		}
		next_block = block->next;
	}

	void *new_ptr = os_malloc(size);

	memcpy(new_ptr, ptr, MINEU(size, block->size));

	os_free(ptr);

	return new_ptr;
}
