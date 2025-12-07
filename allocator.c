/*
 * COMP2221 Systems Programming - Mars Rover Memory Allocator
 *
 * A fault-tolerant dynamic memory allocator designed for the harsh
 * Martian environment. This allocator operates within a single
 * contiguous memory block and provides protection against:
 *
 * - Radiation storms: Detected via checksums with rotation and
 *   redundant size storage in both header and footer
 * - Brownout events: Detected via three-state write commit protocol
 *   (UNWRITTEN -> WRITING -> WRITTEN)
 *
 * Key features:
 * - 40-byte payload alignment relative to heap start
 * - Explicit doubly-linked free list for O(n) allocation
 * - Immediate coalescing of adjacent free blocks
 * - 5-byte free pattern for unused memory identification
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"

/* Alignment requirement for all payload pointers */
#define ALIGNMENT 40

/* Minimum data area size to allow for free list pointers */
#define MIN_BLOCK_SIZE 48

/* Magic numbers for block identification */
#define HDR_MAGIC 0xDEADBEEFU
#define FTR_MAGIC 0xCAFEBABEU

/* Required 5-byte pattern for identifying unused memory */
static const uint8_t FREE_PATTERN[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};

/*
 * Block Header Structure (32 bytes on 64-bit systems)
 *
 * Contains metadata for block management and corruption detection.
 * The checksum field protects all other fields against bit flips.
 */
typedef struct {
    uint32_t magic;       /* Magic number for block identification */
    uint32_t checksum;    /* Rotational checksum for corruption detection */
    size_t size;          /* Total block size including header/footer */
    size_t size_copy;     /* Redundant copy for corruption detection */
    uint32_t allocated;   /* Allocation status: 1=allocated, 0=free */
    uint32_t written;     /* Write state for brownout detection */
} Header;

/* Write commit states for brownout detection */
#define WRITE_STATE_UNWRITTEN 0  /* Block allocated but not written */
#define WRITE_STATE_WRITING   1  /* Write in progress - brownout flag */
#define WRITE_STATE_WRITTEN   2  /* Write completed successfully */

/*
 * Block Footer Structure (24 bytes on 64-bit systems)
 *
 * Mirrors size information for boundary tag coalescing
 * and provides additional corruption detection.
 */
typedef struct {
    uint32_t magic;       /* Magic number for footer identification */
    uint32_t checksum;    /* Checksum protecting footer fields */
    size_t size;          /* Block size (must match header) */
    size_t size_copy;     /* Redundant copy of size */
} Footer;

/*
 * Free List Links Structure
 *
 * Stored in the data area of free blocks to form a doubly-linked
 * list of available blocks. This avoids using header space for
 * pointers that are only needed when the block is free.
 */
typedef struct FreeLinks {
    struct FreeLinks *next;  /* Next free block in list */
    struct FreeLinks *prev;  /* Previous free block in list */
} FreeLinks;

/* Global allocator state */
static uint8_t *heap_start;    /* Start of managed heap */
static uint8_t *heap_end;      /* End of managed heap */
static size_t heap_size;       /* Total heap size in bytes */
static FreeLinks *free_list;   /* Head of free block list */
static bool initialized;       /* Initialization flag */

/* Statistics for debugging and monitoring */
static size_t stat_allocated;     /* Currently allocated bytes */
static size_t stat_corruptions;   /* Number of corruptions detected */

/*
 * Rotate left operation for checksum computation.
 * Provides better bit mixing than simple XOR.
 */
static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/*
 * Compute header checksum using rotation and XOR.
 * More robust than simple XOR as it catches more bit flip patterns.
 */
static uint32_t hdr_checksum(Header *h) {
    uint32_t cs = 0x5A5A5A5AU;  /* Non-zero initial value */
    cs = rotl(cs, 5) ^ h->magic;
    cs = rotl(cs, 7) ^ (uint32_t)(h->size & 0xFFFFFFFFUL);
    cs = rotl(cs, 11) ^ (uint32_t)(h->size >> 32);
    cs = rotl(cs, 13) ^ (uint32_t)(h->size_copy & 0xFFFFFFFFUL);
    cs = rotl(cs, 17) ^ (uint32_t)(h->size_copy >> 32);
    cs = rotl(cs, 19) ^ h->allocated;
    cs = rotl(cs, 23) ^ h->written;
    return cs;
}

/*
 * Compute footer checksum using rotation and XOR.
 */
static uint32_t ftr_checksum(Footer *f) {
    uint32_t cs = 0xA5A5A5A5U;  /* Different initial value from header */
    cs = rotl(cs, 5) ^ f->magic;
    cs = rotl(cs, 7) ^ (uint32_t)(f->size & 0xFFFFFFFFUL);
    cs = rotl(cs, 11) ^ (uint32_t)(f->size >> 32);
    cs = rotl(cs, 13) ^ (uint32_t)(f->size_copy & 0xFFFFFFFFUL);
    cs = rotl(cs, 17) ^ (uint32_t)(f->size_copy >> 32);
    return cs;
}

/*
 * Check if a pointer falls within the managed heap bounds.
 */
static bool in_heap(void *p) {
    if (!p || !initialized) return false;
    uint8_t *ptr = (uint8_t *)p;
    return ptr >= heap_start && ptr < heap_end;
}

/*
 * Get pointer to block footer given header pointer.
 */
static Footer *get_footer(Header *h) {
    return (Footer *)((uint8_t *)h + h->size - sizeof(Footer));
}

/*
 * Get pointer to data area (immediately after header).
 */
static uint8_t *get_data(Header *h) {
    return (uint8_t *)h + sizeof(Header);
}

/*
 * Get aligned payload pointer.
 * Alignment is relative to the original heap start pointer.
 */
static void *get_payload(Header *h) {
    uint8_t *data = get_data(h);
    size_t offset = (size_t)(data - heap_start);
    size_t padding = (ALIGNMENT - (offset % ALIGNMENT)) % ALIGNMENT;
    return data + padding;
}

/*
 * Get usable payload capacity in bytes.
 */
static size_t get_capacity(Header *h) {
    uint8_t *payload = (uint8_t *)get_payload(h);
    uint8_t *data_end = (uint8_t *)get_footer(h);
    if (payload >= data_end) return 0;
    return (size_t)(data_end - payload);
}

/*
 * Fill memory region with the 5-byte free pattern.
 * Used to mark unused memory for identification.
 */
static void fill_pattern(void *ptr, size_t len) {
    uint8_t *p = (uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = FREE_PATTERN[i % 5];
    }
}

/*
 * Validate block header integrity.
 * Checks magic number, size consistency, and checksum.
 */
static bool valid_header(Header *h) {
    /* Check pointer is within heap */
    if (!in_heap(h)) return false;
    if ((uint8_t *)h + sizeof(Header) > heap_end) return false;

    /* Check magic number */
    if (h->magic != HDR_MAGIC) return false;

    /* Check size is reasonable */
    if (h->size < sizeof(Header) + sizeof(Footer)) return false;
    if (h->size > heap_size) return false;

    /* Check redundant size copy matches */
    if (h->size != h->size_copy) return false;

    /* Check block fits in heap */
    if ((uint8_t *)h + h->size > heap_end) return false;

    /* Verify checksum */
    if (h->checksum != hdr_checksum(h)) return false;

    return true;
}

/*
 * Validate block footer integrity.
 * Checks magic number, size consistency with header, and checksum.
 */
static bool valid_footer(Header *h) {
    Footer *f = get_footer(h);

    /* Check pointer is within heap */
    if (!in_heap(f)) return false;
    if ((uint8_t *)f + sizeof(Footer) > heap_end) return false;

    /* Check magic number */
    if (f->magic != FTR_MAGIC) return false;

    /* Check size matches header */
    if (f->size != h->size) return false;
    if (f->size != f->size_copy) return false;

    /* Verify checksum */
    if (f->checksum != ftr_checksum(f)) return false;

    return true;
}

/*
 * Validate entire block (both header and footer).
 */
static bool valid_block(Header *h) {
    return valid_header(h) && valid_footer(h);
}

/*
 * Initialize block header with given parameters.
 * Automatically computes and stores the checksum.
 */
static void init_header(Header *h, size_t bsize, uint32_t alloc,
                        uint32_t written) {
    h->magic = HDR_MAGIC;
    h->size = bsize;
    h->size_copy = bsize;
    h->allocated = alloc;
    h->written = written;
    h->checksum = hdr_checksum(h);
}

/*
 * Initialize block footer based on header information.
 * Automatically computes and stores the checksum.
 */
static void init_footer(Header *h) {
    Footer *f = get_footer(h);
    f->magic = FTR_MAGIC;
    f->size = h->size;
    f->size_copy = h->size;
    f->checksum = ftr_checksum(f);
}

/*
 * Get free list links from block data area.
 */
static FreeLinks *get_links(Header *h) {
    return (FreeLinks *)get_data(h);
}

/*
 * Remove block from free list.
 * Updates prev/next pointers of adjacent list nodes.
 */
static void list_remove(Header *h) {
    FreeLinks *links = get_links(h);
    if (links->prev) {
        links->prev->next = links->next;
    } else {
        free_list = links->next;
    }
    if (links->next) {
        links->next->prev = links->prev;
    }
}

/*
 * Add block to front of free list.
 */
static void list_add(Header *h) {
    FreeLinks *links = get_links(h);
    links->next = free_list;
    links->prev = NULL;
    if (free_list) {
        free_list->prev = links;
    }
    free_list = links;
}

/*
 * Find header for a given payload pointer.
 * Scans heap linearly to find matching block.
 */
static Header *find_header(void *payload) {
    if (!payload || !initialized) return NULL;
    if (!in_heap(payload)) return NULL;

    uint8_t *scan = heap_start;
    size_t min_size = sizeof(Header) + sizeof(Footer);

    while (scan + min_size <= heap_end) {
        Header *h = (Header *)scan;

        /* Check if this looks like a valid header */
        if (h->magic == HDR_MAGIC &&
            h->size >= min_size &&
            h->size <= heap_size &&
            scan + h->size <= heap_end) {

            /* Check if payload matches */
            if (get_payload(h) == payload) {
                return h;
            }
            scan += h->size;
        } else {
            /* Skip ahead if invalid */
            scan += 8;
        }
    }
    return NULL;
}

/*
 * Round up value to given alignment.
 */
static size_t align_up(size_t n, size_t a) {
    return ((n + a - 1) / a) * a;
}

/*
 * Initialize the memory allocator.
 *
 * Sets up the heap with a single free block and fills unused
 * memory with the identification pattern.
 *
 * Returns 0 on success, -1 on failure.
 */
int mm_init(uint8_t *heap, size_t size) {
    /* Validate parameters */
    if (!heap || size < 256) return -1;

    /* Initialize global state */
    heap_start = heap;
    heap_end = heap + size;
    heap_size = size;
    free_list = NULL;
    initialized = true;
    stat_allocated = 0;
    stat_corruptions = 0;

    /* Fill entire heap with free pattern first */
    fill_pattern(heap, size);

    /* Create initial free block spanning entire heap */
    Header *h = (Header *)heap;
    size_t block_size = (size / 8) * 8;  /* Align to 8 bytes */

    init_header(h, block_size, 0, WRITE_STATE_WRITTEN);
    init_footer(h);

    /* Initialize free list with this block */
    FreeLinks *links = get_links(h);
    links->next = NULL;
    links->prev = NULL;
    free_list = links;

    /* Fill data area with pattern (preserve FreeLinks) */
    uint8_t *data = get_data(h);
    size_t data_len = block_size - sizeof(Header) - sizeof(Footer);
    if (data_len > sizeof(FreeLinks)) {
        fill_pattern(data + sizeof(FreeLinks),
                     data_len - sizeof(FreeLinks));
    }

    return 0;
}

/*
 * Find a free block of at least min_size bytes.
 * Uses first-fit strategy. Removes corrupted blocks from list.
 */
static Header *find_fit(size_t min_size) {
    FreeLinks *cur = free_list;
    FreeLinks *prev_link = NULL;

    while (cur) {
        /* Check if pointer is valid */
        if (!in_heap(cur)) {
            /* Corrupted pointer - truncate list */
            if (prev_link) {
                prev_link->next = NULL;
            } else {
                free_list = NULL;
            }
            stat_corruptions++;
            break;
        }

        Header *h = (Header *)((uint8_t *)cur - sizeof(Header));

        /* Validate block integrity */
        if (!valid_block(h)) {
            /* Remove corrupted block from list */
            stat_corruptions++;
            FreeLinks *next = cur->next;
            if (prev_link) {
                prev_link->next = next;
            } else {
                free_list = next;
            }
            if (next && in_heap(next)) {
                next->prev = prev_link;
            }
            cur = next;
            continue;
        }

        /* Check if block is free and large enough */
        if (!h->allocated && h->size >= min_size) {
            return h;
        }

        prev_link = cur;
        cur = cur->next;
    }
    return NULL;
}

/*
 * Split a block if remainder is large enough.
 * Creates a new free block from the excess space.
 */
static void split_block(Header *h, size_t needed) {
    size_t min_rem = sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer);

    /* Only split if remainder can form a valid block */
    if (h->size < needed + min_rem) {
        return;
    }

    size_t new_size = h->size - needed;

    /* Shrink original block */
    init_header(h, needed, h->allocated, h->written);
    init_footer(h);

    /* Create new free block from remainder */
    Header *new_h = (Header *)((uint8_t *)h + needed);
    init_header(new_h, new_size, 0, WRITE_STATE_WRITTEN);
    init_footer(new_h);

    /* Fill new block's data with pattern */
    uint8_t *data = get_data(new_h);
    size_t data_len = new_size - sizeof(Header) - sizeof(Footer);
    if (data_len > sizeof(FreeLinks)) {
        fill_pattern(data + sizeof(FreeLinks),
                     data_len - sizeof(FreeLinks));
    }

    /* Add new block to free list */
    list_add(new_h);
}

/*
 * Coalesce adjacent free blocks.
 * Scans heap linearly and merges consecutive free blocks.
 */
static void coalesce(void) {
    uint8_t *scan = heap_start;
    size_t min_size = sizeof(Header) + sizeof(Footer);

    while (scan + min_size < heap_end) {
        Header *h = (Header *)scan;

        /* Skip if not a valid header */
        if (h->magic != HDR_MAGIC ||
            h->size < min_size ||
            h->size > heap_size ||
            scan + h->size > heap_end) {
            scan += 8;
            continue;
        }

        /* Skip if block is corrupted */
        if (!valid_block(h)) {
            scan += 8;
            continue;
        }

        /* Check next block */
        uint8_t *next_addr = scan + h->size;
        if (next_addr + min_size > heap_end) {
            break;
        }

        Header *next_h = (Header *)next_addr;

        /* Skip if next block is invalid */
        if (next_h->magic != HDR_MAGIC || !valid_block(next_h)) {
            scan = next_addr;
            continue;
        }

        /* Merge if both blocks are free */
        if (!h->allocated && !next_h->allocated) {
            /* Remove both from free list */
            list_remove(h);
            list_remove(next_h);

            /* Create merged block */
            size_t combined = h->size + next_h->size;
            init_header(h, combined, 0, WRITE_STATE_WRITTEN);
            init_footer(h);

            /* Fill data area with pattern */
            uint8_t *data = get_data(h);
            size_t data_len = combined - sizeof(Header) - sizeof(Footer);
            if (data_len > sizeof(FreeLinks)) {
                fill_pattern(data + sizeof(FreeLinks),
                             data_len - sizeof(FreeLinks));
            }

            /* Add merged block to free list */
            list_add(h);

            /* Continue without advancing to check for more merges */
            continue;
        }

        scan = next_addr;
    }
}

/*
 * Allocate a block of at least size bytes.
 *
 * Returns a 40-byte aligned pointer to the payload area,
 * or NULL if allocation fails.
 */
void *mm_malloc(size_t size) {
    if (!initialized || size == 0) return NULL;

    /* Calculate required block size */
    size_t data_needed = size + ALIGNMENT;
    size_t block_size = sizeof(Header) + data_needed + sizeof(Footer);
    block_size = align_up(block_size, 8);

    /* Ensure minimum block size */
    size_t min_block = sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer);
    if (block_size < min_block) {
        block_size = min_block;
    }

    /* Find a suitable free block */
    Header *h = find_fit(block_size);
    if (!h) {
        /* Try coalescing and search again */
        coalesce();
        h = find_fit(block_size);
    }
    if (!h) return NULL;

    /* Remove from free list and split if possible */
    list_remove(h);
    split_block(h, block_size);

    /* Mark as allocated, initially unwritten for brownout detection */
    init_header(h, h->size, 1, WRITE_STATE_UNWRITTEN);
    init_footer(h);

    stat_allocated += h->size;

    /* Get payload and fill with pattern for clean state */
    void *payload = get_payload(h);
    size_t cap = get_capacity(h);
    size_t base = (size_t)((uint8_t *)payload - heap_start);
    for (size_t i = 0; i < cap; i++) {
        ((uint8_t *)payload)[i] = FREE_PATTERN[(base + i) % 5];
    }

    return payload;
}

/*
 * Read data from an allocated block.
 *
 * Performs corruption and brownout detection before reading.
 * Returns number of bytes read, or -1 on error.
 */
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    if (!ptr || !buf) return -1;
    if (len == 0) return 0;

    /* Find and validate block */
    Header *h = find_header(ptr);
    if (!h) return -1;

    if (!valid_block(h)) {
        stat_corruptions++;
        return -1;
    }

    if (!h->allocated) return -1;

    /* Brownout detection: check for interrupted write */
    if (h->written == WRITE_STATE_WRITING) {
        stat_corruptions++;
        return -1;
    }

    /* Bounds check */
    size_t cap = get_capacity(h);
    if (offset >= cap || len > cap - offset) {
        return -1;
    }

    /* Perform read */
    memcpy(buf, (uint8_t *)ptr + offset, len);
    return (int)len;
}

/*
 * Write data to an allocated block.
 *
 * Uses three-state commit protocol for brownout detection.
 * Returns number of bytes written, or -1 on error.
 */
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
    if (!ptr || !src) return -1;
    if (len == 0) return 0;

    /* Find and validate block */
    Header *h = find_header(ptr);
    if (!h) return -1;

    if (!valid_block(h)) {
        stat_corruptions++;
        return -1;
    }

    if (!h->allocated) return -1;

    /* Bounds check */
    size_t cap = get_capacity(h);
    if (offset >= cap || len > cap - offset) {
        return -1;
    }

    /* Brownout detection: ALWAYS set WRITING before memcpy */
    /* This ensures every write operation can be detected if interrupted */
    h->written = WRITE_STATE_WRITING;
    h->checksum = hdr_checksum(h);

    /* Perform the write - if brownout occurs here, state stays WRITING */
    memcpy((uint8_t *)ptr + offset, src, len);

    /* Mark write complete - if brownout occurs here, checksum corrupted */
    h->written = WRITE_STATE_WRITTEN;
    h->checksum = hdr_checksum(h);

    return (int)len;
}

/*
 * Free an allocated block.
 *
 * Returns block to free list and coalesces with neighbors.
 * Handles NULL pointers and double-free safely.
 */
void mm_free(void *ptr) {
    if (!ptr) return;

    /* Find and validate block */
    Header *h = find_header(ptr);
    if (!h) return;

    if (!valid_block(h)) {
        stat_corruptions++;
        return;
    }

    /* Check for double-free */
    if (!h->allocated) return;

    stat_allocated -= h->size;

    /* Mark as free */
    init_header(h, h->size, 0, WRITE_STATE_WRITTEN);
    init_footer(h);

    /* Add to free list */
    list_add(h);

    /* Reset data area to free pattern */
    uint8_t *data = get_data(h);
    size_t data_len = h->size - sizeof(Header) - sizeof(Footer);
    if (data_len > sizeof(FreeLinks)) {
        fill_pattern(data + sizeof(FreeLinks),
                     data_len - sizeof(FreeLinks));
    }

    /* Coalesce with adjacent free blocks */
    coalesce();
}

/*
 * Resize an allocated block.
 *
 * If new size fits in current block, returns same pointer.
 * Otherwise allocates new block, copies data, and frees old.
 */
void *mm_realloc(void *ptr, size_t new_size) {
    /* Handle NULL pointer */
    if (!ptr) return mm_malloc(new_size);

    /* Handle zero size */
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    /* Find and validate block */
    Header *h = find_header(ptr);
    if (!h || !valid_block(h)) {
        stat_corruptions++;
        return NULL;
    }

    /* Check if current block is large enough */
    size_t old_cap = get_capacity(h);
    if (new_size <= old_cap) {
        return ptr;
    }

    /* Allocate new block */
    void *new_ptr = mm_malloc(new_size);
    if (!new_ptr) return NULL;

    /* Copy data from old block */
    size_t copy_size = (old_cap < new_size) ? old_cap : new_size;
    memcpy(new_ptr, ptr, copy_size);

    /* Mark new block as written since data was copied */
    Header *new_h = find_header(new_ptr);
    if (new_h && new_h->written != WRITE_STATE_WRITTEN) {
        new_h->written = WRITE_STATE_WRITTEN;
        new_h->checksum = hdr_checksum(new_h);
    }

    /* Free old block */
    mm_free(ptr);
    return new_ptr;
}

/*
 * Print heap statistics for debugging.
 */
void mm_heap_stats(void) {
    printf("\n=== Heap Statistics ===\n");
    printf("Heap: %p - %p (%zu bytes)\n",
           (void *)heap_start, (void *)heap_end, heap_size);
    printf("Allocated: %zu bytes\n", stat_allocated);
    printf("Corruptions: %zu\n", stat_corruptions);

    /* Count free blocks */
    size_t free_count = 0;
    size_t free_bytes = 0;
    FreeLinks *cur = free_list;

    while (cur && in_heap(cur) && free_count < 10000) {
        Header *h = (Header *)((uint8_t *)cur - sizeof(Header));
        if (valid_block(h)) {
            free_count++;
            free_bytes += h->size;
        }
        cur = cur->next;
    }

    printf("Free blocks: %zu (%zu bytes)\n", free_count, free_bytes);
    printf("=======================\n");
}
