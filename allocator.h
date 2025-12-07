/**
 * @file allocator.h
 * @brief Mars Rover Fault-Tolerant Memory Allocator Interface
 *
 * COMP2221 Systems Programming - Summative Assignment
 * Copyright 2025 COMP2221 Systems Programming
 *
 * This header defines the public API for the Mars Rover memory allocator.
 * The allocator is designed to operate within a single contiguous memory
 * block and provides resilience against radiation storms and brownout events.
 *
 * Features:
 * - 40-byte aligned payload pointers
 * - Corruption detection via checksums
 * - Brownout detection via three-state commit protocol
 * - Double-free and invalid pointer detection
 * - Block quarantine for corrupted memory
 *
 * Usage:
 * 1. Call mm_init() with a pre-allocated memory block
 * 2. Use mm_malloc() to allocate memory
 * 3. Use mm_read()/mm_write() for safe data access
 * 4. Use mm_free() to release memory
 * 5. Optionally use mm_realloc() to resize allocations
 */

#ifndef ALLOCATOR_H_
#define ALLOCATOR_H_

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Initializes the memory allocator over a provided memory block.
 *
 * This function must be called before any other allocator functions.
 * The provided memory block will be used exclusively by the allocator
 * for all metadata and payload storage.
 *
 * Requirements:
 * - heap must not be NULL
 * - heap_size must be at least 256 bytes
 *
 * @param heap      Pointer to the memory block to manage
 * @param heap_size Size of the memory block in bytes
 * @return 0 on success, -1 on failure (invalid parameters)
 */
int mm_init(uint8_t *heap, size_t heap_size);

/**
 * @brief Allocates a block of memory with 40-byte aligned payload.
 *
 * Returns a pointer to a memory region of at least the requested size.
 * The returned pointer is guaranteed to be aligned to 40 bytes relative
 * to the heap start address.
 *
 * @param size Number of bytes to allocate (must be > 0)
 * @return Pointer to allocated memory, or NULL on failure
 */
void *mm_malloc(size_t size);

/**
 * @brief Safely reads data from an allocated block.
 *
 * This function performs corruption detection before reading data.
 * It checks for:
 * - Valid block pointer
 * - Header/footer checksum integrity
 * - Brownout conditions (interrupted writes)
 * - Bounds violations
 *
 * @param ptr    Pointer to the allocated block's payload
 * @param offset Byte offset within the payload to start reading
 * @param buf    Destination buffer for read data
 * @param len    Number of bytes to read
 * @return Number of bytes read on success, -1 on error
 */
int mm_read(void *ptr, size_t offset, void *buf, size_t len);

/**
 * @brief Safely writes data to an allocated block.
 *
 * This function performs corruption detection before writing data.
 * It uses a three-state commit protocol for brownout detection:
 * 1. Sets WRITING state before write
 * 2. Performs the actual write
 * 3. Sets WRITTEN state after completion
 *
 * @param ptr    Pointer to the allocated block's payload
 * @param offset Byte offset within the payload to start writing
 * @param src    Source buffer containing data to write
 * @param len    Number of bytes to write
 * @return Number of bytes written on success, -1 on error
 */
int mm_write(void *ptr, size_t offset, const void *src, size_t len);

/**
 * @brief Frees a previously allocated block.
 *
 * Returns the block to the free pool for reuse. Adjacent free blocks
 * are coalesced to reduce fragmentation.
 *
 * Safety features:
 * - NULL pointers are safely ignored
 * - Double-free is detected and handled safely
 * - Corrupted blocks are quarantined instead of freed
 *
 * @param ptr Pointer to the allocated block's payload (may be NULL)
 */
void mm_free(void *ptr);

/**
 * @brief Resizes a previously allocated block.
 *
 * If the new size fits within the current block, returns the same pointer.
 * Otherwise, allocates a new block, copies the data, and frees the old block.
 *
 * Special cases:
 * - If ptr is NULL, equivalent to mm_malloc(new_size)
 * - If new_size is 0, equivalent to mm_free(ptr) and returns NULL
 *
 * @param ptr      Pointer to the existing allocation (may be NULL)
 * @param new_size New size in bytes
 * @return Pointer to resized block, or NULL on failure
 */
void *mm_realloc(void *ptr, size_t new_size);

/**
 * @brief Outputs current heap usage and integrity statistics.
 *
 * Prints debugging information including:
 * - Heap address range and total size
 * - Currently allocated bytes
 * - Number of corruptions detected
 * - Number of quarantined blocks
 * - Free block count and total free bytes
 *
 * This function is for debugging purposes and carries no credit.
 */
void mm_heap_stats(void);

#endif  /* ALLOCATOR_H_ */
