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
 * - Redundant size storage for storm resilience
 * - Explicit free list with coalescing
 * - Quarantine for corrupted blocks
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
#define MIN_BLOCK_DATA 40

/* Magic values for corruption detection */
#define HDR_MAGIC 0xDEADBEEFU
#define FTR_MAGIC 0xCAFEBABEU
#define CANARY_VALUE 0xABCDEF12U

/* Free memory pattern */
static const uint8_t FREE_PATTERN[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};

/*
 * Block Header - 48 bytes on 64-bit, 32 bytes on 32-bit
 * Stores all metadata needed to manage and validate a block.
 */
typedef struct BlockHdr {
    uint32_t magic;              /* HDR_MAGIC */
    uint32_t canary;             /* CANARY_VALUE */
    size_t data_size;            /* Size of data area (between header and footer) */
    size_t data_size_copy;       /* Redundant copy for corruption detection */
    uint32_t allocated;          /* 1 = allocated, 0 = free */
    uint32_t checksum;           /* XOR checksum for integrity */
    struct BlockHdr *next_free;  /* Next in free list */
    struct BlockHdr *prev_free;  /* Previous in free list */
} BlockHdr;

/*
 * Block Footer - 24 bytes on 64-bit, 16 bytes on 32-bit
 * Provides redundant storage for corruption detection.
 */
typedef struct {
    uint32_t magic;              /* FTR_MAGIC */
    uint32_t canary;             /* CANARY_VALUE */
    size_t data_size;            /* Must match header */
    uint32_t checksum;           /* XOR checksum */
} BlockFtr;

/* Global allocator state */
static struct {
    uint8_t *heap_base;
    uint8_t *heap_limit;
    size_t heap_size;
    BlockHdr *free_list_head;
    BlockHdr *quarantine_head;
    size_t quarantine_count;
    bool is_initialized;
    size_t bytes_allocated;
    size_t bytes_free;
    size_t total_allocs;
    size_t corruption_detections;
} allocator;

/* Compute XOR checksum for header */
static uint32_t compute_hdr_checksum(BlockHdr *h) {
    uint32_t cs = 0;
    cs ^= h->magic;
    cs ^= h->canary;
    cs ^= (uint32_t)(h->data_size & 0xFFFFFFFFU);
    cs ^= (uint32_t)(h->data_size >> 32);
    cs ^= (uint32_t)(h->data_size_copy & 0xFFFFFFFFU);
    cs ^= (uint32_t)(h->data_size_copy >> 32);
    cs ^= h->allocated;
    return cs;
}

/* Compute XOR checksum for footer */
static uint32_t compute_ftr_checksum(BlockFtr *f) {
    uint32_t cs = 0;
    cs ^= f->magic;
    cs ^= f->canary;
    cs ^= (uint32_t)(f->data_size & 0xFFFFFFFFU);
    cs ^= (uint32_t)(f->data_size >> 32);
    return cs;
}

/* Check if pointer is in heap bounds */
static bool ptr_in_heap(void *p) {
    if (!p || !allocator.is_initialized) return false;
    uint8_t *bp = (uint8_t *)p;
    return bp >= allocator.heap_base && bp < allocator.heap_limit;
}

/* Get aligned payload pointer from header */
static void *hdr_to_payload(BlockHdr *h) {
    uint8_t *raw = (uint8_t *)h + sizeof(BlockHdr);
    size_t offset_from_base = (size_t)(raw - allocator.heap_base);
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

/* Get usable payload capacity */
static size_t get_payload_capacity(BlockHdr *h) {
    uint8_t *payload = (uint8_t *)hdr_to_payload(h);
    size_t alignment_padding = (size_t)(payload - (uint8_t *)h - sizeof(BlockHdr));
    if (alignment_padding > h->data_size) return 0;
    return h->data_size - alignment_padding;
}

/* Finalize header checksum */
static void finalize_hdr(BlockHdr *h) {
    h->checksum = 0;
    h->checksum = compute_hdr_checksum(h);
}

/* Initialize footer */
static void init_ftr(BlockFtr *f, size_t data_size) {
    f->magic = FTR_MAGIC;
    f->canary = CANARY_VALUE;
    f->data_size = data_size;
    f->checksum = 0;
    f->checksum = compute_ftr_checksum(f);
}

/* Validate header - returns true if header appears valid */
static bool validate_hdr(BlockHdr *h) {
    if (!ptr_in_heap(h)) return false;
    if (h->magic != HDR_MAGIC) return false;
    if (h->canary != CANARY_VALUE) return false;
    if (h->data_size == 0 || h->data_size > allocator.heap_size) return false;
    if (h->data_size != h->data_size_copy) return false;

    uint32_t saved_cs = h->checksum;
    h->checksum = 0;
    uint32_t computed_cs = compute_hdr_checksum(h);
    h->checksum = saved_cs;

    return saved_cs == computed_cs;
}

/* Validate footer - returns true if footer appears valid */
static bool validate_ftr(BlockFtr *f, BlockHdr *h) {
    if (!ptr_in_heap(f)) return false;
    if ((uint8_t *)f + sizeof(BlockFtr) > allocator.heap_limit) return false;
    if (f->magic != FTR_MAGIC) return false;
    if (f->canary != CANARY_VALUE) return false;
    if (f->data_size != h->data_size) return false;

    uint32_t saved_cs = f->checksum;
    f->checksum = 0;
    uint32_t computed_cs = compute_ftr_checksum(f);
    f->checksum = saved_cs;

    return saved_cs == computed_cs;
}

/* Validate complete block */
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

/* Remove block from free list */
static void remove_from_freelist(BlockHdr *h) {
    if (h->prev_free) {
        h->prev_free->next_free = h->next_free;
    } else {
        allocator.free_list_head = h->next_free;
    }
    if (h->next_free) {
        h->next_free->prev_free = h->prev_free;
    }
    h->next_free = h->prev_free = NULL;
}

/* Add block to front of free list */
static void add_to_freelist(BlockHdr *h) {
    h->next_free = allocator.free_list_head;
    h->prev_free = NULL;
    if (allocator.free_list_head) {
        allocator.free_list_head->prev_free = h;
    }
    allocator.free_list_head = h;
}

/* Quarantine a corrupted block - removes from circulation */
static void quarantine_add(BlockHdr *h) {
    if (!h) return;

    /* Remove from free list if present */
    BlockHdr *cur = allocator.free_list_head;
    BlockHdr *prev = NULL;
    int iter = 0;

    while (cur && iter++ < 10000) {
        if (!ptr_in_heap(cur)) break;
        if (cur == h) {
            if (prev) prev->next_free = cur->next_free;
            else allocator.free_list_head = cur->next_free;
            if (cur->next_free && ptr_in_heap(cur->next_free)) {
                cur->next_free->prev_free = prev;
            }
            break;
        }
        prev = cur;
        if (!ptr_in_heap(cur->next_free) && cur->next_free != NULL) break;
        cur = cur->next_free;
    }

    /* Add to quarantine */
    h->next_free = allocator.quarantine_head;
    h->prev_free = NULL;
    allocator.quarantine_head = h;
    allocator.quarantine_count++;
    allocator.corruption_detections++;
}

/* Find header for a payload pointer */
static BlockHdr *payload_to_hdr(void *payload) {
    if (!payload || !allocator.is_initialized) return NULL;
    if (!ptr_in_heap(payload)) return NULL;

    uint8_t *scan = allocator.heap_base;
    int iter = 0;

    while (scan + sizeof(BlockHdr) + sizeof(BlockFtr) <= allocator.heap_limit && iter++ < 100000) {
        BlockHdr *h = (BlockHdr *)scan;

        if (h->magic == HDR_MAGIC &&
            h->data_size > 0 &&
            h->data_size <= allocator.heap_size) {

            if (hdr_to_payload(h) == payload) {
                return h;
            }

            size_t block_total = sizeof(BlockHdr) + h->data_size + sizeof(BlockFtr);
            if (scan + block_total <= allocator.heap_limit) {
                scan += block_total;
                continue;
            }
        }

        scan += sizeof(void *);
    }

    return NULL;
}

/* Round up to multiple of alignment */
static size_t round_up(size_t val, size_t mult) {
    return ((val + mult - 1) / mult) * mult;
}

/* Find a free block with enough space */
static BlockHdr *find_free(size_t needed) {
    BlockHdr *cur = allocator.free_list_head;
    int iter = 0;

    while (cur && iter++ < 10000) {
        if (!ptr_in_heap(cur)) break;

        BlockHdr *next = cur->next_free;
        if (next && !ptr_in_heap(next)) {
            cur->next_free = NULL;
            next = NULL;
        }

        if (!validate_block(cur)) {
            quarantine_add(cur);
            cur = next;
            continue;
        }

        if (!cur->allocated && cur->data_size >= needed) {
            return cur;
        }

        cur = next;
    }

    return NULL;
}

/* Split block if it's too big */
static void split_block(BlockHdr *h, size_t needed) {
    size_t min_remainder = sizeof(BlockHdr) + MIN_BLOCK_DATA + sizeof(BlockFtr);

    if (h->data_size < needed + min_remainder) {
        return;
    }

    size_t new_data_size = h->data_size - needed - sizeof(BlockHdr) - sizeof(BlockFtr);
    uint8_t *new_loc = (uint8_t *)h + sizeof(BlockHdr) + needed + sizeof(BlockFtr);

    BlockHdr *new_h = (BlockHdr *)new_loc;
    new_h->magic = HDR_MAGIC;
    new_h->canary = CANARY_VALUE;
    new_h->data_size = new_data_size;
    new_h->data_size_copy = new_data_size;
    new_h->allocated = 0;
    new_h->next_free = new_h->prev_free = NULL;
    finalize_hdr(new_h);
    init_ftr(hdr_to_ftr(new_h), new_data_size);
    write_free_pattern(hdr_to_payload(new_h), get_payload_capacity(new_h));

    /* Update original block */
    h->data_size = needed;
    h->data_size_copy = needed;
    finalize_hdr(h);
    init_ftr(hdr_to_ftr(h), needed);

    add_to_freelist(new_h);
}

/* Coalesce adjacent free blocks */
static void coalesce(void) {
    uint8_t *scan = allocator.heap_base;
    int iter = 0;

    while (scan + sizeof(BlockHdr) + sizeof(BlockFtr) <= allocator.heap_limit && iter++ < 100000) {
        BlockHdr *cur = (BlockHdr *)scan;

        if (cur->magic != HDR_MAGIC || cur->data_size == 0 || cur->data_size > allocator.heap_size) {
            scan += sizeof(void *);
            continue;
        }

        if (!validate_block(cur)) {
            quarantine_add(cur);
            scan += sizeof(void *);
            continue;
        }

        size_t block_total = sizeof(BlockHdr) + cur->data_size + sizeof(BlockFtr);
        uint8_t *next_addr = scan + block_total;

        if (next_addr + sizeof(BlockHdr) + sizeof(BlockFtr) > allocator.heap_limit) {
            break;
        }

        BlockHdr *next = (BlockHdr *)next_addr;

        if (next->magic != HDR_MAGIC || next->data_size == 0 || next->data_size > allocator.heap_size) {
            scan = next_addr;
            continue;
        }

        if (!validate_block(next)) {
            scan = next_addr;
            continue;
        }

        if (!cur->allocated && !next->allocated) {
            remove_from_freelist(next);

            size_t combined = cur->data_size + sizeof(BlockHdr) + sizeof(BlockFtr) + next->data_size;
            cur->data_size = combined;
            cur->data_size_copy = combined;
            finalize_hdr(cur);
            init_ftr(hdr_to_ftr(cur), combined);
            write_free_pattern(hdr_to_payload(cur), get_payload_capacity(cur));
            continue;
        }

        scan = next_addr;
    }
}

/* Initialize the allocator */
int mm_init(uint8_t *heap, size_t heap_size) {
    if (!heap || heap_size < 512) {
        return -1;
    }

    memset(&allocator, 0, sizeof(allocator));
    allocator.heap_base = heap;
    allocator.heap_limit = heap + heap_size;
    allocator.heap_size = heap_size;
    allocator.is_initialized = true;

    size_t overhead = sizeof(BlockHdr) + sizeof(BlockFtr);
    size_t usable = heap_size - overhead;
    usable = (usable / 8) * 8;

    BlockHdr *h = (BlockHdr *)heap;
    h->magic = HDR_MAGIC;
    h->canary = CANARY_VALUE;
    h->data_size = usable;
    h->data_size_copy = usable;
    h->allocated = 0;
    h->next_free = h->prev_free = NULL;
    finalize_hdr(h);
    init_ftr(hdr_to_ftr(h), usable);
    write_free_pattern(hdr_to_payload(h), get_payload_capacity(h));

    allocator.free_list_head = h;
    allocator.bytes_free = usable;

    return 0;
}

/* Allocate memory */
void *mm_malloc(size_t size) {
    if (!allocator.is_initialized || size == 0) {
        return NULL;
    }

    size_t needed = size + ALIGNMENT;
    needed = round_up(needed, 8);
    if (needed < MIN_BLOCK_DATA) needed = MIN_BLOCK_DATA;
    if (needed > allocator.heap_size) return NULL;

    BlockHdr *h = find_free(needed);
    if (!h) {
        coalesce();
        h = find_free(needed);
    }
    if (!h) return NULL;

    split_block(h, needed);
    remove_from_freelist(h);

    h->allocated = 1;
    finalize_hdr(h);
    init_ftr(hdr_to_ftr(h), h->data_size);

    allocator.bytes_allocated += h->data_size;
    allocator.bytes_free -= h->data_size;
    allocator.total_allocs++;

    void *payload = hdr_to_payload(h);
    memset(payload, 0, size);

    return payload;
}

/* Safely read from allocated memory */
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    if (!ptr || !buf) return -1;
    if (len == 0) return 0;

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return -1;

    if (!validate_block(h)) {
        quarantine_add(h);
        return -1;
    }

    if (!h->allocated) return -1;

    size_t capacity = get_payload_capacity(h);
    if (offset >= capacity || offset + len > capacity) {
        return -1;
    }

    memcpy(buf, (uint8_t *)ptr + offset, len);
    return (int)len;
}

/* Safely write to allocated memory */
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
    if (!ptr || !src) return -1;
    if (len == 0) return 0;

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return -1;

    if (!validate_block(h)) {
        quarantine_add(h);
        return -1;
    }

    if (!h->allocated) return -1;

    size_t capacity = get_payload_capacity(h);
    if (offset >= capacity || offset + len > capacity) {
        return -1;
    }

    memcpy((uint8_t *)ptr + offset, src, len);
    return (int)len;
}

/* Free allocated memory */
void mm_free(void *ptr) {
    if (!ptr) return;

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return;

    if (!validate_block(h)) {
        quarantine_add(h);
        return;
    }

    if (!h->allocated) return;  /* Double-free detection */

    h->allocated = 0;
    finalize_hdr(h);
    write_free_pattern(hdr_to_payload(h), get_payload_capacity(h));

    add_to_freelist(h);

    allocator.bytes_allocated -= h->data_size;
    allocator.bytes_free += h->data_size;

    coalesce();
}

/* Resize allocated memory */
void *mm_realloc(void *ptr, size_t new_size) {
    if (!ptr) return mm_malloc(new_size);
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    BlockHdr *h = payload_to_hdr(ptr);
    if (!h) return NULL;

    if (!validate_block(h)) {
        quarantine_add(h);
        return NULL;
    }

    size_t old_capacity = get_payload_capacity(h);
    if (new_size <= old_capacity) return ptr;

    void *new_ptr = mm_malloc(new_size);
    if (!new_ptr) return NULL;

    memcpy(new_ptr, ptr, old_capacity);
    mm_free(ptr);

    return new_ptr;
}

/* Print heap statistics */
void mm_heap_stats(void) {
    printf("\n=== Heap Statistics ===\n");
    printf("Heap Start: %p\n", (void *)allocator.heap_base);
    printf("Heap Size: %zu bytes\n", allocator.heap_size);
    printf("Total Allocated: %zu bytes\n", allocator.bytes_allocated);
    printf("Total Free: %zu bytes\n", allocator.bytes_free);
    printf("Total Allocations: %zu\n", allocator.total_allocs);
    printf("Corruption Detections: %zu\n", allocator.corruption_detections);
    printf("Quarantined Blocks: %zu\n", allocator.quarantine_count);

    size_t free_count = 0, free_total = 0, max_free = 0;
    BlockHdr *cur = allocator.free_list_head;

    while (cur && ptr_in_heap(cur)) {
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
