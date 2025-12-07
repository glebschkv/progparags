/*
 * COMP2221 Systems Programming - Mars Rover Memory Allocator
 *
 * Fault-tolerant allocator detecting:
 * - Radiation storms (bit flips) via checksums and redundant storage
 * - Brownout events (partial writes) via pattern detection and metadata consistency
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"

#define ALIGNMENT 40
#define MIN_BLOCK_SIZE 48

/* Magic numbers */
#define HDR_MAGIC 0xDEADBEEFU
#define FTR_MAGIC 0xCAFEBABEU

/* Required 5-byte free pattern */
static const uint8_t FREE_PATTERN[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};

/*
 * Block Header (32 bytes on 64-bit)
 */
typedef struct {
    uint32_t magic;           /* HDR_MAGIC */
    uint32_t checksum;        /* XOR checksum */
    size_t size;              /* Total block size */
    size_t size_copy;         /* Redundant copy */
    uint32_t allocated;       /* 1 = allocated, 0 = free */
    uint32_t written;         /* 1 = data written, 0 = not yet written (brownout detection) */
} Header;

/* Write commit states for brownout detection */
#define WRITE_STATE_UNWRITTEN 0    /* Never written - OK to read (free pattern) */
#define WRITE_STATE_WRITING   1    /* Write in progress - brownout if seen on read */
#define WRITE_STATE_WRITTEN   2    /* Write completed - OK to read */

/*
 * Block Footer (24 bytes on 64-bit)
 */
typedef struct {
    uint32_t magic;
    uint32_t checksum;
    size_t size;
    size_t size_copy;
} Footer;

/*
 * Free list links - stored in payload area
 */
typedef struct FreeLinks {
    struct FreeLinks *next;
    struct FreeLinks *prev;
} FreeLinks;

/* Global state */
static uint8_t *heap_start;
static uint8_t *heap_end;
static size_t heap_size;
static FreeLinks *free_list;
static bool initialized;

/* Statistics */
static size_t stat_allocated;
static size_t stat_corruptions;

/* Compute header checksum */
static uint32_t hdr_checksum(Header *h) {
    uint32_t cs = 0;
    cs ^= h->magic;
    cs ^= (uint32_t)(h->size & 0xFFFFFFFFUL);
    cs ^= (uint32_t)(h->size >> 32);
    cs ^= (uint32_t)(h->size_copy & 0xFFFFFFFFUL);
    cs ^= (uint32_t)(h->size_copy >> 32);
    cs ^= h->allocated;
    cs ^= h->written;
    return cs;
}

/* Compute footer checksum */
static uint32_t ftr_checksum(Footer *f) {
    uint32_t cs = 0;
    cs ^= f->magic;
    cs ^= (uint32_t)(f->size & 0xFFFFFFFFUL);
    cs ^= (uint32_t)(f->size >> 32);
    cs ^= (uint32_t)(f->size_copy & 0xFFFFFFFFUL);
    cs ^= (uint32_t)(f->size_copy >> 32);
    return cs;
}

/* Check if pointer is in heap */
static bool in_heap(void *p) {
    return p && initialized && (uint8_t *)p >= heap_start && (uint8_t *)p < heap_end;
}

/* Get footer from header */
static Footer *get_footer(Header *h) {
    return (Footer *)((uint8_t *)h + h->size - sizeof(Footer));
}

/* Get data area */
static uint8_t *get_data(Header *h) {
    return (uint8_t *)h + sizeof(Header);
}

/* Get aligned payload - relative to ORIGINAL heap pointer */
static void *get_payload(Header *h) {
    uint8_t *data = get_data(h);
    size_t offset = (size_t)(data - heap_start);
    size_t padding = (ALIGNMENT - (offset % ALIGNMENT)) % ALIGNMENT;
    return data + padding;
}

/* Get payload capacity */
static size_t get_capacity(Header *h) {
    uint8_t *payload = (uint8_t *)get_payload(h);
    uint8_t *data_end = (uint8_t *)get_footer(h);
    if (payload >= data_end) return 0;
    return (size_t)(data_end - payload);
}

/* Fill memory with the 5-byte free pattern */
static void fill_pattern(void *ptr, size_t len) {
    uint8_t *p = (uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = FREE_PATTERN[i % 5];
    }
}

/* Validate header */
static bool valid_header(Header *h) {
    if (!in_heap(h)) return false;
    if ((uint8_t *)h + sizeof(Header) > heap_end) return false;
    if (h->magic != HDR_MAGIC) return false;
    if (h->size < sizeof(Header) + sizeof(Footer)) return false;
    if (h->size > heap_size) return false;
    if (h->size != h->size_copy) return false;
    if ((uint8_t *)h + h->size > heap_end) return false;
    if (h->checksum != hdr_checksum(h)) return false;
    return true;
}

/* Validate footer */
static bool valid_footer(Header *h) {
    Footer *f = get_footer(h);
    if (!in_heap(f)) return false;
    if ((uint8_t *)f + sizeof(Footer) > heap_end) return false;
    if (f->magic != FTR_MAGIC) return false;
    if (f->size != h->size) return false;
    if (f->size != f->size_copy) return false;
    if (f->checksum != ftr_checksum(f)) return false;
    return true;
}

/* Validate entire block */
static bool valid_block(Header *h) {
    return valid_header(h) && valid_footer(h);
}

/* Initialize header */
static void init_header(Header *h, size_t block_size, uint32_t alloc, uint32_t written) {
    h->magic = HDR_MAGIC;
    h->size = block_size;
    h->size_copy = block_size;
    h->allocated = alloc;
    h->written = written;
    h->checksum = hdr_checksum(h);
}

/* Initialize footer */
static void init_footer(Header *h) {
    Footer *f = get_footer(h);
    f->magic = FTR_MAGIC;
    f->size = h->size;
    f->size_copy = h->size;
    f->checksum = ftr_checksum(f);
}

/* Get free links */
static FreeLinks *get_links(Header *h) {
    return (FreeLinks *)get_data(h);
}

/* Remove from free list */
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

/* Add to free list */
static void list_add(Header *h) {
    FreeLinks *links = get_links(h);
    links->next = free_list;
    links->prev = NULL;
    if (free_list) {
        free_list->prev = links;
    }
    free_list = links;
}

/* Find header for payload */
static Header *find_header(void *payload) {
    if (!payload || !initialized) return NULL;
    if (!in_heap(payload)) return NULL;

    uint8_t *scan = heap_start;
    while (scan + sizeof(Header) + sizeof(Footer) <= heap_end) {
        Header *h = (Header *)scan;

        if (h->magic == HDR_MAGIC &&
            h->size >= sizeof(Header) + sizeof(Footer) &&
            h->size <= heap_size &&
            scan + h->size <= heap_end) {

            if (get_payload(h) == payload) {
                return h;
            }
            scan += h->size;
        } else {
            scan += 8;
        }
    }
    return NULL;
}

/* Round up */
static size_t align_up(size_t n, size_t a) {
    return ((n + a - 1) / a) * a;
}

/* Initialize allocator */
int mm_init(uint8_t *heap, size_t size) {
    if (!heap || size < 256) return -1;

    heap_start = heap;
    heap_end = heap + size;
    heap_size = size;
    free_list = NULL;
    initialized = true;
    stat_allocated = 0;
    stat_corruptions = 0;

    /* Fill entire heap with the 5-byte pattern first */
    fill_pattern(heap, size);

    /* Create initial free block */
    Header *h = (Header *)heap;
    size_t block_size = (size / 8) * 8;

    init_header(h, block_size, 0, WRITE_STATE_WRITTEN);
    init_footer(h);

    /* Set up free links first */
    FreeLinks *links = get_links(h);
    links->next = NULL;
    links->prev = NULL;
    free_list = links;

    /* Fill data area with pattern (skip FreeLinks at start) */
    uint8_t *data = get_data(h);
    size_t data_len = block_size - sizeof(Header) - sizeof(Footer);
    if (data_len > sizeof(FreeLinks)) {
        fill_pattern(data + sizeof(FreeLinks), data_len - sizeof(FreeLinks));
    }

    return 0;
}

/* Find free block */
static Header *find_fit(size_t min_size) {
    FreeLinks *cur = free_list;
    FreeLinks *prev_link = NULL;

    while (cur) {
        if (!in_heap(cur)) {
            if (prev_link) prev_link->next = NULL;
            else free_list = NULL;
            stat_corruptions++;
            break;
        }

        Header *h = (Header *)((uint8_t *)cur - sizeof(Header));

        if (!valid_block(h)) {
            stat_corruptions++;
            FreeLinks *next = cur->next;
            if (prev_link) prev_link->next = next;
            else free_list = next;
            if (next && in_heap(next)) next->prev = prev_link;
            cur = next;
            continue;
        }

        if (!h->allocated && h->size >= min_size) {
            return h;
        }

        prev_link = cur;
        cur = cur->next;
    }
    return NULL;
}

/* Split block */
static void split_block(Header *h, size_t needed) {
    size_t min_remainder = sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer);

    if (h->size < needed + min_remainder) {
        return;
    }

    size_t new_size = h->size - needed;

    /* Shrink original */
    init_header(h, needed, h->allocated, h->written);
    init_footer(h);

    /* Create new free block */
    Header *new_h = (Header *)((uint8_t *)h + needed);
    init_header(new_h, new_size, 0, WRITE_STATE_WRITTEN);
    init_footer(new_h);

    /* Fill data area with pattern (skip FreeLinks at start) */
    uint8_t *data = get_data(new_h);
    size_t data_len = new_size - sizeof(Header) - sizeof(Footer);
    if (data_len > sizeof(FreeLinks)) {
        fill_pattern(data + sizeof(FreeLinks), data_len - sizeof(FreeLinks));
    }

    list_add(new_h);
}

/* Coalesce adjacent free blocks */
static void coalesce(void) {
    uint8_t *scan = heap_start;

    while (scan + sizeof(Header) + sizeof(Footer) < heap_end) {
        Header *h = (Header *)scan;

        if (h->magic != HDR_MAGIC || h->size < sizeof(Header) + sizeof(Footer) ||
            h->size > heap_size || scan + h->size > heap_end) {
            scan += 8;
            continue;
        }

        if (!valid_block(h)) {
            scan += 8;
            continue;
        }

        uint8_t *next_addr = scan + h->size;
        if (next_addr + sizeof(Header) + sizeof(Footer) > heap_end) {
            break;
        }

        Header *next_h = (Header *)next_addr;

        if (next_h->magic != HDR_MAGIC || !valid_block(next_h)) {
            scan = next_addr;
            continue;
        }

        if (!h->allocated && !next_h->allocated) {
            /* Remove both from free list before merging */
            list_remove(h);
            list_remove(next_h);

            size_t combined = h->size + next_h->size;
            init_header(h, combined, 0, WRITE_STATE_WRITTEN);
            init_footer(h);

            /* Fill payload with pattern (after free list pointers) */
            uint8_t *data = get_data(h);
            size_t data_len = h->size - sizeof(Header) - sizeof(Footer);
            /* Skip the FreeLinks area at start of data */
            if (data_len > sizeof(FreeLinks)) {
                fill_pattern(data + sizeof(FreeLinks), data_len - sizeof(FreeLinks));
            }

            /* Re-add to free list */
            list_add(h);

            continue;
        }

        scan = next_addr;
    }
}

/* Allocate memory */
void *mm_malloc(size_t size) {
    if (!initialized || size == 0) return NULL;

    size_t data_needed = size + ALIGNMENT;
    size_t block_size = sizeof(Header) + data_needed + sizeof(Footer);
    block_size = align_up(block_size, 8);

    if (block_size < sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer)) {
        block_size = sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer);
    }

    Header *h = find_fit(block_size);
    if (!h) {
        coalesce();
        h = find_fit(block_size);
    }
    if (!h) return NULL;

    list_remove(h);
    split_block(h, block_size);

    /* Mark as allocated - initially unwritten (brownout detection) */
    init_header(h, h->size, 1, WRITE_STATE_UNWRITTEN);
    init_footer(h);

    stat_allocated += h->size;

    void *payload = get_payload(h);

    /* Fill payload with free pattern to ensure clean state for brownout detection */
    size_t cap = get_capacity(h);
    size_t base_offset = (size_t)((uint8_t *)payload - heap_start);
    for (size_t i = 0; i < cap; i++) {
        ((uint8_t *)payload)[i] = FREE_PATTERN[(base_offset + i) % 5];
    }

    return payload;
}

/* Read from block */
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
    if (!ptr || !buf) return -1;
    if (len == 0) return 0;

    Header *h = find_header(ptr);
    if (!h) return -1;

    if (!valid_block(h)) {
        stat_corruptions++;
        return -1;
    }

    if (!h->allocated) return -1;

    /* Brownout detection: check write commit state */
    if (h->written == WRITE_STATE_WRITING) {
        /* Write was in progress but interrupted - brownout detected */
        stat_corruptions++;
        return -1;
    }

    size_t cap = get_capacity(h);
    if (offset >= cap || len > cap - offset) {
        return -1;
    }

    memcpy(buf, (uint8_t *)ptr + offset, len);
    return (int)len;
}

/* Write to block */
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
    if (!ptr || !src) return -1;
    if (len == 0) return 0;

    Header *h = find_header(ptr);
    if (!h) return -1;

    if (!valid_block(h)) {
        stat_corruptions++;
        return -1;
    }

    if (!h->allocated) return -1;

    size_t cap = get_capacity(h);
    if (offset >= cap || len > cap - offset) {
        return -1;
    }

    /* Brownout detection: mark write in progress BEFORE the memcpy */
    if (h->written != WRITE_STATE_WRITTEN) {
        h->written = WRITE_STATE_WRITING;
        h->checksum = hdr_checksum(h);
    }

    /* Perform the actual write */
    memcpy((uint8_t *)ptr + offset, src, len);

    /* Mark write as complete AFTER the memcpy */
    if (h->written == WRITE_STATE_WRITING) {
        h->written = WRITE_STATE_WRITTEN;
        h->checksum = hdr_checksum(h);
    }

    return (int)len;
}

/* Free block */
void mm_free(void *ptr) {
    if (!ptr) return;

    Header *h = find_header(ptr);
    if (!h) return;

    if (!valid_block(h)) {
        stat_corruptions++;
        return;
    }

    if (!h->allocated) return;

    stat_allocated -= h->size;

    /* Mark as free */
    init_header(h, h->size, 0, WRITE_STATE_WRITTEN);
    init_footer(h);

    /* Add to free list first (so FreeLinks are set) */
    list_add(h);

    /* Reset data area to free pattern (skip FreeLinks at start) */
    uint8_t *data = get_data(h);
    size_t data_len = h->size - sizeof(Header) - sizeof(Footer);
    if (data_len > sizeof(FreeLinks)) {
        fill_pattern(data + sizeof(FreeLinks), data_len - sizeof(FreeLinks));
    }

    coalesce();
}

/* Realloc */
void *mm_realloc(void *ptr, size_t new_size) {
    if (!ptr) return mm_malloc(new_size);
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    Header *h = find_header(ptr);
    if (!h || !valid_block(h)) {
        stat_corruptions++;
        return NULL;
    }

    size_t old_cap = get_capacity(h);
    if (new_size <= old_cap) {
        return ptr;
    }

    void *new_ptr = mm_malloc(new_size);
    if (!new_ptr) return NULL;

    /* Copy old data */
    size_t copy_size = (old_cap < new_size) ? old_cap : new_size;
    memcpy(new_ptr, ptr, copy_size);

    /* Mark new block as written (data was copied) */
    Header *new_h = find_header(new_ptr);
    if (new_h && new_h->written != WRITE_STATE_WRITTEN) {
        new_h->written = WRITE_STATE_WRITTEN;
        new_h->checksum = hdr_checksum(new_h);
    }

    mm_free(ptr);
    return new_ptr;
}

/* Print stats */
void mm_heap_stats(void) {
    printf("\n=== Heap Statistics ===\n");
    printf("Heap: %p - %p (%zu bytes)\n", (void *)heap_start, (void *)heap_end, heap_size);
    printf("Allocated: %zu bytes\n", stat_allocated);
    printf("Corruptions: %zu\n", stat_corruptions);

    size_t free_count = 0, free_bytes = 0;
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
