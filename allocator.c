/*
 * ============================================================================
 * COMP2221 Systems Programming - Mars Rover Memory Allocator
 * ============================================================================
 *
 * A fault-tolerant memory allocator designed for Mars rover operations.
 * Handles radiation-induced bit flips and power brownouts safely.
 *
 * Key features:
 * - 40-byte alignment for all payloads
 * - Header/footer with magic numbers and checksums for corruption detection
 * - Commit flags for brownout detection
 * - Redundant size storage for storm resilience
 * - Explicit free list with coalescing
 *
 * ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"

/* Alignment requirement - all payloads aligned to 40 bytes */
#define ALIGNMENT 40

/* Minimum block data size */
#define MIN_BLOCK_DATA 80

/* Magic values for corruption detection */
#define HDR_MAGIC_VALID   0xDEADBEEFU
#define HDR_MAGIC_WRITING 0xBEEFDEADU  /* Indicates write in progress */
#define FTR_MAGIC_VALID   0xCAFEBABEU
#define CANARY_VALUE      0xABCDEF12U

/* Commit status */
#define COMMIT_PENDING 0x00000000U
#define COMMIT_DONE    0x12345678U

/* Free memory pattern */
static const uint8_t FREE_PATTERN[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};

/*
 * Block Header - stores all metadata needed to manage and validate a block.
 *
 * The checksum is computed such that XOR of all fields (including checksum) == 0
 * This allows validation without modifying the header.
 */
typedef struct BlockHdr {
    uint32_t magic;              /* HDR_MAGIC_VALID when committed */
    uint32_t canary;             /* CANARY_VALUE */
    size_t data_size;            /* Size of data area (between header and footer) */
    size_t data_size_backup;     /* Redundant copy for corruption detection */
    uint32_t allocated;          /* 1 = allocated, 0 = free */
    uint32_t commit;             /* COMMIT_DONE when write complete (brownout detection) */
    uint32_t checksum;           /* XOR checksum (XOR of all fields == 0 when valid) */
    uint32_t padding;            /* Alignment padding */
    struct BlockHdr *next_free;  /* Next in free list */
    struct BlockHdr *prev_free;  /* Previous in free list */
} BlockHdr;

/*
 * Block Footer - provides redundant storage for corruption detection.
 */
typedef struct {
    uint32_t magic;              /* FTR_MAGIC_VALID */
    uint32_t canary;             /* CANARY_VALUE */
    size_t data_size;            /* Must match header */
    uint32_t commit;             /* COMMIT_DONE when write complete */
    uint32_t checksum;           /* XOR checksum */
} BlockFtr;

/* Global allocator state */
static struct {
    uint8_t *heap_base;
    uint8_t *heap_limit;
    size_t heap_size;
    BlockHdr *free_list_head;
    size_t quarantine_count;
    bool is_initialized;
    size_t bytes_allocated;
    size_t bytes_free;
    size_t total_allocs;
    size_t corruption_detections;
} g_alloc;

/*
 * Compute XOR checksum for header - includes all fields except checksum itself.
 * The checksum value is set so that XOR of all fields including checksum == 0.
 */
static uint32_t compute_hdr_xor(BlockHdr *h) {
    uint32_t cs = 0;
    cs ^= h->magic;
    cs ^= h->canary;
    cs ^= (uint32_t)(h->data_size & 0xFFFFFFFFUL);
    cs ^= (uint32_t)((h->data_size >> 16) >> 16);  /* Portable 64-bit shift */
    cs ^= (uint32_t)(h->data_size_backup & 0xFFFFFFFFUL);
    cs ^= (uint32_t)((h->data_size_backup >> 16) >> 16);
    cs ^= h->allocated;
    cs ^= h->commit;
    cs ^= h->padding;
    /* Include pointer addresses in checksum for corruption detection */
    cs ^= (uint32_t)((uintptr_t)h->next_free & 0xFFFFFFFFUL);
    cs ^= (uint32_t)(((uintptr_t)h->next_free >> 16) >> 16);
    cs ^= (uint32_t)((uintptr_t)h->prev_free & 0xFFFFFFFFUL);
    cs ^= (uint32_t)(((uintptr_t)h->prev_free >> 16) >> 16);
    return cs;
}

/*
 * Compute XOR checksum for footer.
 */
static uint32_t compute_ftr_xor(BlockFtr *f) {
    uint32_t cs = 0;
    cs ^= f->magic;
    cs ^= f->canary;
    cs ^= (uint32_t)(f->data_size & 0xFFFFFFFFUL);
    cs ^= (uint32_t)((f->data_size >> 16) >> 16);
    cs ^= f->commit;
    return cs;
}

/* Check if pointer is within heap bounds */
static bool ptr_in_heap(void *p) {
    if (!p || !g_alloc.is_initialized) return false;
    uint8_t *bp = (uint8_t *)p;
    return bp >= g_alloc.heap_base && bp < g_alloc.heap_limit;
}

/* Check if a range is within heap bounds */
static bool range_in_heap(void *start, size_t len) {
    if (!start || len == 0) return false;
    uint8_t *s = (uint8_t *)start;
    uint8_t *e = s + len;
    return s >= g_alloc.heap_base && e <= g_alloc.heap_limit && s < e;
}

/* Get aligned payload pointer from header */
static void *hdr_to_payload(BlockHdr *h) {
    uint8_t *raw = (uint8_t *)h + sizeof(BlockHdr);
    size_t offset_from_base = (size_t)(raw - g_alloc.heap_base);
    size_t padding = 0;
    if (offset_from_base % ALIGNMENT != 0) {
        padding = ALIGNMENT - (offset_from_base % ALIGNMENT);
    }
    return raw + padding;
}

/* Get footer pointer from header */
static BlockFtr *hdr_to_ftr(BlockHdr *h) {
    return (BlockFtr *)((uint8_t *)h + sizeof(BlockHdr) + h->data_size);
}

/* Calculate alignment padding for a header */
static size_t get_alignment_padding(BlockHdr *h) {
    uint8_t *raw = (uint8_t *)h + sizeof(BlockHdr);
    size_t offset_from_base = (size_t)(raw - g_alloc.heap_base);
    if (offset_from_base % ALIGNMENT == 0) return 0;
    return ALIGNMENT - (offset_from_base % ALIGNMENT);
}

/* Get usable payload capacity */
static size_t get_payload_capacity(BlockHdr *h) {
    size_t align_pad = get_alignment_padding(h);
    if (align_pad >= h->data_size) return 0;
    return h->data_size - align_pad;
}

/*
 * Finalize header - compute and store checksum.
 * Sets checksum such that XOR of all fields == 0.
 */
static void finalize_hdr(BlockHdr *h) {
    h->checksum = 0;
    h->checksum = compute_hdr_xor(h);  /* Now XOR of all fields == 0 */
}

/*
 * Initialize footer with proper values and checksum.
 */
static void init_ftr(BlockFtr *f, size_t data_size) {
    f->magic = FTR_MAGIC_VALID;
    f->canary = CANARY_VALUE;
    f->data_size = data_size;
    f->commit = COMMIT_DONE;
    f->checksum = 0;
    f->checksum = compute_ftr_xor(f);  /* Now XOR of all fields == 0 */
}

/*
 * Validate header - does NOT modify the header.
 * Returns true if header appears valid and uncorrupted.
 */
static bool validate_hdr(BlockHdr *h) {
    if (!range_in_heap(h, sizeof(BlockHdr))) return false;

    /* Check magic - must be valid (not writing) */
    if (h->magic != HDR_MAGIC_VALID) return false;

    /* Check canary */
    if (h->canary != CANARY_VALUE) return false;

    /* Check commit status (brownout detection) */
    if (h->commit != COMMIT_DONE) return false;

    /* Check data size is reasonable */
    if (h->data_size == 0 || h->data_size > g_alloc.heap_size) return false;

    /* Check redundant size copy matches */
    if (h->data_size != h->data_size_backup) return false;

    /* Verify checksum: XOR of all fields should be 0 */
    uint32_t xor_check = compute_hdr_xor(h) ^ h->checksum;
    return xor_check == 0;
}

/*
 * Validate footer - does NOT modify the footer.
 */
static bool validate_ftr(BlockFtr *f, BlockHdr *h) {
    if (!range_in_heap(f, sizeof(BlockFtr))) return false;

    /* Check magic */
    if (f->magic != FTR_MAGIC_VALID) return false;

    /* Check canary */
    if (f->canary != CANARY_VALUE) return false;

    /* Check commit status (brownout detection) */
    if (f->commit != COMMIT_DONE) return false;

    /* Check data size matches header */
    if (f->data_size != h->data_size) return false;

    /* Verify checksum */
    uint32_t xor_check = compute_ftr_xor(f) ^ f->checksum;
    return xor_check == 0;
}

/*
 * Validate complete block (header + footer).
 */
static bool validate_block(BlockHdr *h) {
    if (!validate_hdr(h)) return false;

    BlockFtr *f = hdr_to_ftr(h);
    return validate_ftr(f, h);
}

/* Write free pattern to payload area */
static void write_free_pattern(void *ptr, size_t size) {
    uint8_t *p = (uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = FREE_PATTERN[i % 5];
    }
}

/* Remove block from free list - updates checksums for modified headers */
static void remove_from_freelist(BlockHdr *h) {
    BlockHdr *prev_blk = h->prev_free;
    BlockHdr *next_blk = h->next_free;

    if (prev_blk && ptr_in_heap(prev_blk)) {
        prev_blk->next_free = next_blk;
        finalize_hdr(prev_blk);  /* Update checksum after modifying pointer */
    } else {
        g_alloc.free_list_head = next_blk;
    }

    if (next_blk && ptr_in_heap(next_blk)) {
        next_blk->prev_free = prev_blk;
        finalize_hdr(next_blk);  /* Update checksum after modifying pointer */
    }

    h->next_free = NULL;
    h->prev_free = NULL;
}

/* Add block to front of free list - updates checksums */
static void add_to_freelist(BlockHdr *h) {
    h->next_free = g_alloc.free_list_head;
    h->prev_free = NULL;

    if (g_alloc.free_list_head && ptr_in_heap(g_alloc.free_list_head)) {
        g_alloc.free_list_head->prev_free = h;
        finalize_hdr(g_alloc.free_list_head);  /* Update checksum */
    }

    g_alloc.free_list_head = h;
}

/*
 * Scan heap to find header for a given payload pointer.
 * This is safer than pointer arithmetic which could be corrupted.
 */
static BlockHdr *payload_to_hdr(void *payload) {
    if (!payload || !g_alloc.is_initialized) return NULL;
    if (!ptr_in_heap(payload)) return NULL;

    uint8_t *scan = g_alloc.heap_base;
    size_t max_iterations = g_alloc.heap_size / sizeof(void *);
    size_t iter = 0;

    while (scan + sizeof(BlockHdr) + sizeof(BlockFtr) <= g_alloc.heap_limit &&
           iter++ < max_iterations) {
        BlockHdr *h = (BlockHdr *)scan;

        /* Check if this looks like a valid header */
        if ((h->magic == HDR_MAGIC_VALID || h->magic == HDR_MAGIC_WRITING) &&
            h->data_size > 0 && h->data_size <= g_alloc.heap_size) {

            /* Check if this header's payload matches what we're looking for */
            if (hdr_to_payload(h) == payload) {
                return h;
            }

            /* Move to next block */
            size_t block_total = sizeof(BlockHdr) + h->data_size + sizeof(BlockFtr);
            if (scan + block_total <= g_alloc.heap_limit) {
                scan += block_total;
                continue;
            }
        }

        /* Fallback: step forward slowly */
        scan += sizeof(void *);
    }

    return NULL;
}

/* Round up to multiple of given value */
static size_t round_up(size_t val, size_t mult) {
    return ((val + mult - 1) / mult) * mult;
}

/*
 * Find a free block with at least 'needed' bytes of data space.
 * Removes corrupted blocks from the free list.
 */
static BlockHdr *find_free_block(size_t needed) {
    BlockHdr *cur = g_alloc.free_list_head;
    BlockHdr *prev = NULL;
    size_t max_iter = g_alloc.heap_size / sizeof(void *);
    size_t iter = 0;

    while (cur && iter++ < max_iter) {
        if (!ptr_in_heap(cur)) {
            /* Corrupted pointer - fix the list */
            if (prev) {
                prev->next_free = NULL;
                finalize_hdr(prev);
            } else {
                g_alloc.free_list_head = NULL;
            }
            break;
        }

        BlockHdr *next = cur->next_free;

        /* Validate current block */
        if (!validate_block(cur)) {
            /* Corrupted - remove from list */
            g_alloc.corruption_detections++;
            g_alloc.quarantine_count++;

            if (prev) {
                prev->next_free = next;
                finalize_hdr(prev);
            } else {
                g_alloc.free_list_head = next;
            }

            if (next && ptr_in_heap(next)) {
                next->prev_free = prev;
                finalize_hdr(next);
            }

            cur = next;
            continue;
        }

        /* Check if block is free and large enough */
        if (!cur->allocated && cur->data_size >= needed) {
            return cur;
        }

        prev = cur;
        cur = next;
    }

    return NULL;
}

/*
 * Split a block if it's significantly larger than needed.
 * Creates a new free block from the remainder.
 */
static void split_block(BlockHdr *h, size_t needed) {
    size_t min_split = sizeof(BlockHdr) + MIN_BLOCK_DATA + sizeof(BlockFtr);

    if (h->data_size < needed + min_split) {
        return;  /* Not enough space to split */
    }

    /* Calculate new block location and size */
    size_t new_data_size = h->data_size - needed - sizeof(BlockHdr) - sizeof(BlockFtr);
    uint8_t *new_loc = (uint8_t *)h + sizeof(BlockHdr) + needed + sizeof(BlockFtr);

    /* Initialize new block header (mark as writing first) */
    BlockHdr *new_h = (BlockHdr *)new_loc;
    new_h->magic = HDR_MAGIC_WRITING;  /* Mark as in-progress */
    new_h->canary = CANARY_VALUE;
    new_h->data_size = new_data_size;
    new_h->data_size_backup = new_data_size;
    new_h->allocated = 0;
    new_h->commit = COMMIT_PENDING;
    new_h->padding = 0;
    new_h->next_free = NULL;
    new_h->prev_free = NULL;

    /* Initialize footer */
    init_ftr(hdr_to_ftr(new_h), new_data_size);

    /* Mark header as complete */
    new_h->commit = COMMIT_DONE;
    new_h->magic = HDR_MAGIC_VALID;
    finalize_hdr(new_h);

    /* Fill with free pattern */
    write_free_pattern(hdr_to_payload(new_h), get_payload_capacity(new_h));

    /* Update original block */
    h->data_size = needed;
    h->data_size_backup = needed;
    finalize_hdr(h);
    init_ftr(hdr_to_ftr(h), needed);

    /* Add new block to free list */
    add_to_freelist(new_h);
    finalize_hdr(new_h);  /* Update checksum after adding to list */
}

/*
 * Coalesce adjacent free blocks.
 * Walks the heap linearly and merges consecutive free blocks.
 */
static void coalesce_blocks(void) {
    uint8_t *scan = g_alloc.heap_base;
    size_t max_iter = g_alloc.heap_size / sizeof(void *);
    size_t iter = 0;

    while (scan + sizeof(BlockHdr) + sizeof(BlockFtr) <= g_alloc.heap_limit &&
           iter++ < max_iter) {

        BlockHdr *cur = (BlockHdr *)scan;

        /* Check if this looks like a valid block */
        if (cur->magic != HDR_MAGIC_VALID || cur->data_size == 0 ||
            cur->data_size > g_alloc.heap_size) {
            scan += sizeof(void *);
            continue;
        }

        if (!validate_block(cur)) {
            scan += sizeof(void *);
            continue;
        }

        /* Find next block */
        size_t block_total = sizeof(BlockHdr) + cur->data_size + sizeof(BlockFtr);
        uint8_t *next_addr = scan + block_total;

        if (next_addr + sizeof(BlockHdr) + sizeof(BlockFtr) > g_alloc.heap_limit) {
            break;
        }

        BlockHdr *next = (BlockHdr *)next_addr;

        if (next->magic != HDR_MAGIC_VALID || next->data_size == 0 ||
            next->data_size > g_alloc.heap_size) {
            scan = next_addr;
            continue;
        }

        if (!validate_block(next)) {
            scan = next_addr;
            continue;
        }

        /* If both blocks are free, merge them */
        if (!cur->allocated && !next->allocated) {
            /* Remove next from free list */
            remove_from_freelist(next);

            /* Combine sizes: cur data + header + footer + next data */
            size_t combined = cur->data_size + sizeof(BlockHdr) + sizeof(BlockFtr) + next->data_size;

            /* Update current block */
            cur->magic = HDR_MAGIC_WRITING;
            cur->data_size = combined;
            cur->data_size_backup = combined;
            cur->commit = COMMIT_DONE;
            cur->magic = HDR_MAGIC_VALID;
            finalize_hdr(cur);

            init_ftr(hdr_to_ftr(cur), combined);
            write_free_pattern(hdr_to_payload(cur), get_payload_capacity(cur));

            /* Don't advance scan - check if we can merge with next block too */
            continue;
        }

        scan = next_addr;
    }
}

/*
 * Initialize the allocator with a memory block.
 */
int mm_init(uint8_t *heap, size_t heap_size) {
    if (!heap || heap_size < 512) {
        return -1;
    }

    /* Clear allocator state */
    memset(&g_alloc, 0, sizeof(g_alloc));
    g_alloc.heap_base = heap;
    g_alloc.heap_limit = heap + heap_size;
    g_alloc.heap_size = heap_size;
    g_alloc.is_initialized = true;

    /* Calculate usable space */
    size_t overhead = sizeof(BlockHdr) + sizeof(BlockFtr);
    size_t usable = heap_size - overhead;
    usable = (usable / 8) * 8;  /* Align to 8 bytes */

    /* Initialize first block (mark as writing first for brownout protection) */
    BlockHdr *h = (BlockHdr *)heap;
    h->magic = HDR_MAGIC_WRITING;
    h->canary = CANARY_VALUE;
    h->data_size = usable;
    h->data_size_backup = usable;
    h->allocated = 0;
    h->commit = COMMIT_PENDING;
    h->padding = 0;
    h->next_free = NULL;
    h->prev_free = NULL;

    /* Initialize footer */
    init_ftr(hdr_to_ftr(h), usable);

    /* Mark header as complete */
    h->commit = COMMIT_DONE;
    h->magic = HDR_MAGIC_VALID;
    finalize_hdr(h);

    /* Fill with free pattern */
    write_free_pattern(hdr_to_payload(h), get_payload_capacity(h));

    /* Set up free list */
    g_alloc.free_list_head = h;
    g_alloc.bytes_free = usable;

    return 0;
}

/*
 * Allocate memory.
 */
void *mm_malloc(size_t size) {
    if (!g_alloc.is_initialized || size == 0) {
        return NULL;
    }

    /* Calculate needed data size with alignment padding */
    size_t needed = size + ALIGNMENT;  /* Extra space for alignment */
    needed = round_up(needed, 8);
    if (needed < MIN_BLOCK_DATA) needed = MIN_BLOCK_DATA;
    if (needed > g_alloc.heap_size) return NULL;

    /* Find a free block */
    BlockHdr *h = find_free_block(needed);
    if (!h) {
        coalesce_blocks();
        h = find_free_block(needed);
    }
    if (!h) return NULL;

    /* Split if block is too large */
    split_block(h, needed);

    /* Remove from free list */
    remove_from_freelist(h);

    /* Mark as allocated (with brownout protection) */
    h->magic = HDR_MAGIC_WRITING;
    h->allocated = 1;
    h->commit = COMMIT_DONE;
    h->magic = HDR_MAGIC_VALID;
    finalize_hdr(h);
    init_ftr(hdr_to_ftr(h), h->data_size);

    /* Update statistics */
    g_alloc.bytes_allocated += h->data_size;
    g_alloc.bytes_free -= h->data_size;
    g_alloc.total_allocs++;

    /* Return aligned payload pointer, zeroed */
    void *payload = hdr_to_payload(h);
    memset(payload, 0, size);

    return payload;
}

/*
 * Safely read from allocated memory.
 * Validates block integrity before reading.
 */
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    if (!ptr || !buf) return -1;
    if (len == 0) return 0;

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return -1;

    /* Validate block integrity */
    if (!validate_block(h)) {
        g_alloc.corruption_detections++;
        return -1;
    }

    /* Must be allocated */
    if (!h->allocated) return -1;

    /* Bounds check (safe from overflow) */
    size_t capacity = get_payload_capacity(h);
    if (offset >= capacity) return -1;
    if (len > capacity - offset) return -1;

    memcpy(buf, (uint8_t *)ptr + offset, len);
    return (int)len;
}

/*
 * Safely write to allocated memory.
 * Validates block integrity before writing.
 */
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
    if (!ptr || !src) return -1;
    if (len == 0) return 0;

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return -1;

    /* Validate block integrity */
    if (!validate_block(h)) {
        g_alloc.corruption_detections++;
        return -1;
    }

    /* Must be allocated */
    if (!h->allocated) return -1;

    /* Bounds check (safe from overflow) */
    size_t capacity = get_payload_capacity(h);
    if (offset >= capacity) return -1;
    if (len > capacity - offset) return -1;

    memcpy((uint8_t *)ptr + offset, src, len);
    return (int)len;
}

/*
 * Free allocated memory.
 * Handles corruption and double-free safely.
 */
void mm_free(void *ptr) {
    if (!ptr) return;

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return;

    /* Check for corruption */
    if (!validate_block(h)) {
        g_alloc.corruption_detections++;
        g_alloc.quarantine_count++;
        return;  /* Don't touch corrupted block */
    }

    /* Double-free detection */
    if (!h->allocated) return;

    /* Mark as free (with brownout protection) */
    h->magic = HDR_MAGIC_WRITING;
    h->allocated = 0;
    h->commit = COMMIT_DONE;
    h->magic = HDR_MAGIC_VALID;
    finalize_hdr(h);

    /* Fill payload with free pattern */
    write_free_pattern(hdr_to_payload(h), get_payload_capacity(h));

    /* Add to free list */
    add_to_freelist(h);
    finalize_hdr(h);  /* Update checksum after adding to list */

    /* Update statistics */
    g_alloc.bytes_allocated -= h->data_size;
    g_alloc.bytes_free += h->data_size;

    /* Try to coalesce */
    coalesce_blocks();
}

/*
 * Resize allocated memory.
 * Preserves existing data up to min(old_size, new_size).
 */
void *mm_realloc(void *ptr, size_t new_size) {
    if (!ptr) return mm_malloc(new_size);
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return NULL;

    if (!validate_block(h)) {
        g_alloc.corruption_detections++;
        return NULL;
    }

    size_t old_capacity = get_payload_capacity(h);

    /* If current block is large enough, keep it */
    if (new_size <= old_capacity) {
        return ptr;
    }

    /* Allocate new block */
    void *new_ptr = mm_malloc(new_size);
    if (!new_ptr) return NULL;

    /* Copy old data */
    memcpy(new_ptr, ptr, old_capacity);

    /* Free old block */
    mm_free(ptr);

    return new_ptr;
}

/*
 * Print heap statistics for debugging.
 */
void mm_heap_stats(void) {
    printf("\n=== Heap Statistics ===\n");
    printf("Heap Start: %p\n", (void *)g_alloc.heap_base);
    printf("Heap Size: %zu bytes\n", g_alloc.heap_size);
    printf("Total Allocated: %zu bytes\n", g_alloc.bytes_allocated);
    printf("Total Free: %zu bytes\n", g_alloc.bytes_free);
    printf("Total Allocations: %zu\n", g_alloc.total_allocs);
    printf("Corruption Detections: %zu\n", g_alloc.corruption_detections);
    printf("Quarantined Blocks: %zu\n", g_alloc.quarantine_count);

    /* Count free list */
    size_t free_count = 0;
    size_t free_total = 0;
    size_t max_free = 0;
    BlockHdr *cur = g_alloc.free_list_head;
    size_t max_iter = 10000;

    while (cur && ptr_in_heap(cur) && free_count < max_iter) {
        free_count++;
        free_total += cur->data_size;
        if (cur->data_size > max_free) max_free = cur->data_size;
        cur = cur->next_free;
    }

    printf("Free Blocks: %zu\n", free_count);
    printf("Free List Size: %zu bytes\n", free_total);
    printf("Largest Free Block: %zu bytes\n", max_free);
    printf("======================\n");
}
