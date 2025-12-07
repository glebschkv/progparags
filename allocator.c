/*
 * COMP2221 Systems Programming - Mars Rover Memory Allocator
 *
 * A fault-tolerant memory allocator that detects:
 * - Radiation storms (bit flips) via checksums
 * - Brownout events (partial writes) via header/footer consistency
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"

#define ALIGNMENT 40
#define MIN_BLOCK_SIZE 40

/* Magic numbers */
#define HDR_MAGIC 0xDEADBEEFU
#define FTR_MAGIC 0xCAFEBABEU

/*
 * Block Header (32 bytes on 64-bit)
 * Pointers stored in data area, not header, so checksum doesn't change on list ops
 */
typedef struct {
    uint32_t magic;         /* HDR_MAGIC */
    uint32_t checksum;      /* XOR of magic, size copies, allocated */
    size_t size;            /* Total block size (header + data + footer) */
    size_t size_copy;       /* Redundant copy for corruption detection */
    uint32_t allocated;     /* 1 = allocated, 0 = free */
    uint32_t reserved;      /* Padding */
} Header;

/*
 * Block Footer (24 bytes on 64-bit)
 */
typedef struct {
    uint32_t magic;         /* FTR_MAGIC */
    uint32_t checksum;      /* XOR of magic, size copies */
    size_t size;            /* Must match header */
    size_t size_copy;       /* Redundant copy */
} Footer;

/*
 * Free block links - stored at start of data area (not in header)
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

/* Get data area from header */
static uint8_t *get_data(Header *h) {
    return (uint8_t *)h + sizeof(Header);
}

/* Get aligned payload pointer */
static void *get_payload(Header *h) {
    uint8_t *data = get_data(h);
    size_t offset = (size_t)(data - heap_start);
    size_t padding = (ALIGNMENT - (offset % ALIGNMENT)) % ALIGNMENT;
    return data + padding;
}

/* Get payload capacity (usable bytes) */
static size_t get_capacity(Header *h) {
    uint8_t *payload = (uint8_t *)get_payload(h);
    uint8_t *data_end = (uint8_t *)get_footer(h);
    if (payload >= data_end) return 0;
    return (size_t)(data_end - payload);
}

/* Validate header */
static bool valid_header(Header *h) {
    if (!in_heap(h)) return false;
    if ((uint8_t *)h + sizeof(Header) > heap_end) return false;
    if (h->magic != HDR_MAGIC) return false;
    if (h->size < sizeof(Header) + sizeof(Footer)) return false;
    if (h->size > heap_size) return false;
    if (h->size != h->size_copy) return false;  /* Corruption or brownout */
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
    if (f->size != h->size) return false;  /* Header/footer mismatch = corruption or brownout */
    if (f->size != f->size_copy) return false;
    if (f->checksum != ftr_checksum(f)) return false;
    return true;
}

/* Validate entire block */
static bool valid_block(Header *h) {
    return valid_header(h) && valid_footer(h);
}

/* Initialize header */
static void init_header(Header *h, size_t block_size, uint32_t alloc) {
    h->magic = HDR_MAGIC;
    h->size = block_size;
    h->size_copy = block_size;
    h->allocated = alloc;
    h->reserved = 0;
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

/* Get free links from block */
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

/* Add to front of free list */
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

    /* Scan blocks to find matching payload */
    uint8_t *scan = heap_start;
    while (scan + sizeof(Header) + sizeof(Footer) <= heap_end) {
        Header *h = (Header *)scan;

        if (h->magic == HDR_MAGIC &&
            h->size >= sizeof(Header) + sizeof(Footer) &&
            h->size <= heap_size) {

            if (get_payload(h) == payload) {
                return h;
            }

            /* Move to next block */
            if (scan + h->size <= heap_end) {
                scan += h->size;
                continue;
            }
        }
        /* Corrupted - try next alignment */
        scan += 8;
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

    /* Create initial free block */
    Header *h = (Header *)heap;
    size_t block_size = (size / 8) * 8;  /* Align to 8 */

    init_header(h, block_size, 0);
    init_footer(h);

    /* Set up free links */
    FreeLinks *links = get_links(h);
    links->next = NULL;
    links->prev = NULL;
    free_list = links;

    return 0;
}

/* Find free block of at least min_size bytes */
static Header *find_fit(size_t min_size) {
    FreeLinks *cur = free_list;
    FreeLinks *prev_link = NULL;

    while (cur) {
        if (!in_heap(cur)) {
            /* Corrupted pointer - truncate list */
            if (prev_link) prev_link->next = NULL;
            else free_list = NULL;
            stat_corruptions++;
            break;
        }

        Header *h = (Header *)((uint8_t *)cur - sizeof(Header));

        if (!valid_block(h)) {
            /* Corrupted block - remove from list */
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

/* Split block if remainder is large enough */
static void split_block(Header *h, size_t needed) {
    size_t min_remainder = sizeof(Header) + ALIGNMENT + sizeof(FreeLinks) + sizeof(Footer);

    if (h->size < needed + min_remainder) {
        return;
    }

    size_t new_size = h->size - needed;

    /* Shrink original block */
    init_header(h, needed, h->allocated);
    init_footer(h);

    /* Create new free block */
    Header *new_h = (Header *)((uint8_t *)h + needed);
    init_header(new_h, new_size, 0);
    init_footer(new_h);

    /* Add new block to free list */
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

        /* Merge if both free */
        if (!h->allocated && !next_h->allocated) {
            list_remove(next_h);

            size_t combined = h->size + next_h->size;
            init_header(h, combined, 0);
            init_footer(h);
            /* Don't advance - try to merge more */
            continue;
        }

        scan = next_addr;
    }
}

/* Allocate memory */
void *mm_malloc(size_t size) {
    if (!initialized || size == 0) return NULL;

    /* Calculate required block size */
    size_t data_needed = size + ALIGNMENT;  /* Extra for alignment */
    size_t block_size = sizeof(Header) + data_needed + sizeof(Footer);
    block_size = align_up(block_size, 8);

    if (block_size < sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer)) {
        block_size = sizeof(Header) + MIN_BLOCK_SIZE + sizeof(Footer);
    }

    /* Find fit */
    Header *h = find_fit(block_size);
    if (!h) {
        coalesce();
        h = find_fit(block_size);
    }
    if (!h) return NULL;

    /* Remove from free list */
    list_remove(h);

    /* Split if too large */
    split_block(h, block_size);

    /* Mark as allocated */
    init_header(h, h->size, 1);
    init_footer(h);

    stat_allocated += h->size;

    void *payload = get_payload(h);
    memset(payload, 0, size);

    return payload;
}

/* Read from allocated block */
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

    size_t cap = get_capacity(h);
    if (offset >= cap || len > cap - offset) {
        return -1;
    }

    memcpy(buf, (uint8_t *)ptr + offset, len);
    return (int)len;
}

/* Write to allocated block */
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

    memcpy((uint8_t *)ptr + offset, src, len);
    return (int)len;
}

/* Free allocated block */
void mm_free(void *ptr) {
    if (!ptr) return;

    Header *h = find_header(ptr);
    if (!h) return;

    if (!valid_block(h)) {
        stat_corruptions++;
        return;
    }

    /* Double-free check */
    if (!h->allocated) return;

    stat_allocated -= h->size;

    /* Mark as free */
    init_header(h, h->size, 0);
    init_footer(h);

    /* Add to free list */
    list_add(h);

    /* Coalesce */
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

    memcpy(new_ptr, ptr, old_cap);
    mm_free(ptr);

    return new_ptr;
}

/* Print stats */
void mm_heap_stats(void) {
    printf("\n=== Heap Statistics ===\n");
    printf("Heap: %p - %p (%zu bytes)\n", (void *)heap_start, (void *)heap_end, heap_size);
    printf("Allocated: %zu bytes\n", stat_allocated);
    printf("Corruptions detected: %zu\n", stat_corruptions);

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
