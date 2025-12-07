/**
 * @file allocator.c
 * @brief Mars Rover Fault-Tolerant Memory Allocator
 *
 * COMP2221 Systems Programming - Summative Assignment
 *
 * This module implements a robust dynamic memory allocator designed for
 * the harsh Martian environment. The allocator operates within a single
 * contiguous memory block and provides protection against:
 *
 * - Radiation storms: Random bit-flips detected via checksums with
 *   redundant size storage in both header and footer structures
 * - Brownout events: Power interruptions detected via a three-state
 *   commit protocol (UNWRITTEN -> WRITING -> WRITTEN)
 *
 * Design Features:
 * - 40-byte payload alignment relative to heap start address
 * - Explicit doubly-linked free list for efficient block management
 * - Immediate coalescing of adjacent free blocks
 * - 5-byte free pattern (0xDE, 0xAD, 0xBE, 0xEF, 0x99) for unused memory
 * - Block quarantine system for corrupted memory isolation
 *
 * @author COMP2221 Student
 * @date 2025
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"

/*===========================================================================*/
/*                              CONSTANTS                                     */
/*===========================================================================*/

/** Alignment requirement for all payload pointers (in bytes) */
#define ALIGNMENT 40

/** Minimum data area size to accommodate free list pointers */
#define MIN_DATA_SIZE 48

/** Magic number for header identification and validation */
#define HEADER_MAGIC 0xDEADBEEFU

/** Magic number for footer identification and validation */
#define FOOTER_MAGIC 0xCAFEBABEU

/** Magic number for quarantined (corrupted) block identification */
#define QUARANTINE_MAGIC 0xDEADDEADU

/** Minimum heap size required for initialization */
#define MIN_HEAP_SIZE 256

/** Maximum number of blocks that can be quarantined */
#define MAX_QUARANTINE 64

/*===========================================================================*/
/*                          WRITE STATE CONSTANTS                             */
/*===========================================================================*/

/**
 * Write commit states for brownout detection.
 * Uses a three-state protocol to detect interrupted metadata writes.
 */
#define STATE_UNWRITTEN 0x00000000U  /**< Block allocated, not yet written */
#define STATE_WRITING   0xAAAAAAAAU  /**< Write in progress (brownout flag) */
#define STATE_WRITTEN   0x55555555U  /**< Write completed successfully */

/*===========================================================================*/
/*                          5-BYTE FREE PATTERN                               */
/*===========================================================================*/

/**
 * Required 5-byte pattern for identifying unused memory regions.
 * This pattern must be used to fill all deallocated memory.
 */
static const uint8_t FREE_PATTERN[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};

/*===========================================================================*/
/*                          DATA STRUCTURES                                   */
/*===========================================================================*/

/**
 * @struct Header
 * @brief Block header structure for metadata storage.
 *
 * Each allocated or free block begins with this header structure.
 * The header contains all necessary metadata for block management
 * and corruption detection.
 *
 * Size: 32 bytes on 64-bit systems
 */
typedef struct {
    uint32_t magic;       /**< Magic number for block identification */
    uint32_t checksum;    /**< Rotational checksum for corruption detection */
    size_t   size;        /**< Total block size including header and footer */
    size_t   size_backup; /**< Redundant size copy for corruption detection */
    uint32_t is_alloc;    /**< Allocation status: 1 = allocated, 0 = free */
    uint32_t write_state; /**< Write state for brownout detection */
} Header;

/**
 * @struct Footer
 * @brief Block footer structure for boundary tag coalescing.
 *
 * Each block ends with this footer structure. The footer mirrors
 * the size information from the header to enable backward traversal
 * and provides additional corruption detection.
 *
 * Size: 24 bytes on 64-bit systems
 */
typedef struct {
    uint32_t magic;       /**< Magic number for footer identification */
    uint32_t checksum;    /**< Checksum protecting footer fields */
    size_t   size;        /**< Block size (must match header) */
    size_t   size_backup; /**< Redundant size copy for validation */
} Footer;

/**
 * @struct FreeLinks
 * @brief Free list node structure stored in free block data area.
 *
 * This structure is stored at the beginning of the data area in
 * free blocks, forming a doubly-linked list of available blocks.
 */
typedef struct FreeLinks {
    struct FreeLinks *next; /**< Pointer to next free block */
    struct FreeLinks *prev; /**< Pointer to previous free block */
} FreeLinks;

/*===========================================================================*/
/*                          GLOBAL STATE                                      */
/*===========================================================================*/

/** Pointer to the start of the managed heap */
static uint8_t *heap_start = NULL;

/** Pointer to the end of the managed heap (exclusive) */
static uint8_t *heap_end = NULL;

/** Total size of the managed heap in bytes */
static size_t heap_total_size = 0;

/** Head pointer for the free block linked list */
static FreeLinks *free_list_head = NULL;

/** Flag indicating whether the allocator has been initialized */
static bool is_initialized = false;

/** Array storing pointers to quarantined (corrupted) blocks */
static void *quarantine_list[MAX_QUARANTINE];

/** Current number of quarantined blocks */
static size_t quarantine_count = 0;

/** Statistics: total bytes currently allocated */
static size_t stats_allocated_bytes = 0;

/** Statistics: number of corruption events detected */
static size_t stats_corruption_count = 0;

/*===========================================================================*/
/*                          UTILITY FUNCTIONS                                 */
/*===========================================================================*/

/**
 * @brief Performs a 32-bit left rotation.
 *
 * This operation provides better bit mixing than simple XOR
 * for checksum computation.
 *
 * @param value The value to rotate
 * @param bits  Number of bits to rotate left
 * @return The rotated value
 */
static uint32_t rotate_left(uint32_t value, int bits)
{
    return (value << bits) | (value >> (32 - bits));
}

/**
 * @brief Computes checksum for a block header.
 *
 * Uses rotation and XOR operations to create a checksum that
 * can detect single-bit flips in the header fields.
 *
 * @param hdr Pointer to the header structure
 * @return The computed checksum value
 */
static uint32_t compute_header_checksum(const Header *hdr)
{
    uint32_t cs = 0x5A5A5A5AU;  /* Non-zero seed value */

    cs = rotate_left(cs, 5) ^ hdr->magic;
    cs = rotate_left(cs, 7) ^ (uint32_t)(hdr->size & 0xFFFFFFFFUL);
    cs = rotate_left(cs, 11) ^ (uint32_t)(hdr->size >> 32);
    cs = rotate_left(cs, 13) ^ (uint32_t)(hdr->size_backup & 0xFFFFFFFFUL);
    cs = rotate_left(cs, 17) ^ (uint32_t)(hdr->size_backup >> 32);
    cs = rotate_left(cs, 19) ^ hdr->is_alloc;
    cs = rotate_left(cs, 23) ^ hdr->write_state;

    return cs;
}

/**
 * @brief Computes checksum for a block footer.
 *
 * Uses a different seed than the header checksum to ensure
 * header and footer checksums are independent.
 *
 * @param ftr Pointer to the footer structure
 * @return The computed checksum value
 */
static uint32_t compute_footer_checksum(const Footer *ftr)
{
    uint32_t cs = 0xA5A5A5A5U;  /* Different seed from header */

    cs = rotate_left(cs, 5) ^ ftr->magic;
    cs = rotate_left(cs, 7) ^ (uint32_t)(ftr->size & 0xFFFFFFFFUL);
    cs = rotate_left(cs, 11) ^ (uint32_t)(ftr->size >> 32);
    cs = rotate_left(cs, 13) ^ (uint32_t)(ftr->size_backup & 0xFFFFFFFFUL);
    cs = rotate_left(cs, 17) ^ (uint32_t)(ftr->size_backup >> 32);

    return cs;
}

/**
 * @brief Checks if a pointer is within the managed heap bounds.
 *
 * @param ptr Pointer to check
 * @return true if pointer is within heap, false otherwise
 */
static bool is_within_heap(const void *ptr)
{
    if (ptr == NULL || !is_initialized) {
        return false;
    }

    const uint8_t *p = (const uint8_t *)ptr;
    return (p >= heap_start) && (p < heap_end);
}

/**
 * @brief Rounds up a value to the specified alignment.
 *
 * @param value     The value to align
 * @param alignment The alignment boundary (must be power of 2)
 * @return The aligned value
 */
static size_t align_up(size_t value, size_t alignment)
{
    return ((value + alignment - 1) / alignment) * alignment;
}

/**
 * @brief Fills a memory region with the 5-byte free pattern.
 *
 * This function fills the specified memory region with the
 * repeating 5-byte pattern {0xDE, 0xAD, 0xBE, 0xEF, 0x99}.
 *
 * @param ptr Pointer to the start of the region
 * @param len Length of the region in bytes
 */
static void fill_free_pattern(void *ptr, size_t len)
{
    uint8_t *p = (uint8_t *)ptr;
    size_t i;

    for (i = 0; i < len; i++) {
        p[i] = FREE_PATTERN[i % 5];
    }
}

/*===========================================================================*/
/*                      BLOCK ACCESSOR FUNCTIONS                              */
/*===========================================================================*/

/**
 * @brief Gets the footer pointer for a block.
 *
 * @param hdr Pointer to the block header
 * @return Pointer to the block footer
 */
static Footer *get_block_footer(Header *hdr)
{
    return (Footer *)((uint8_t *)hdr + hdr->size - sizeof(Footer));
}

/**
 * @brief Gets the data area pointer for a block.
 *
 * The data area starts immediately after the header.
 *
 * @param hdr Pointer to the block header
 * @return Pointer to the start of the data area
 */
static uint8_t *get_data_area(Header *hdr)
{
    return (uint8_t *)hdr + sizeof(Header);
}

/**
 * @brief Gets the aligned payload pointer for a block.
 *
 * The payload pointer is aligned to ALIGNMENT bytes relative
 * to the heap start address.
 *
 * @param hdr Pointer to the block header
 * @return Aligned payload pointer
 */
static void *get_aligned_payload(Header *hdr)
{
    uint8_t *data = get_data_area(hdr);
    size_t offset_from_heap = (size_t)(data - heap_start);
    size_t padding = (ALIGNMENT - (offset_from_heap % ALIGNMENT)) % ALIGNMENT;

    return data + padding;
}

/**
 * @brief Gets the usable capacity of a block's payload area.
 *
 * @param hdr Pointer to the block header
 * @return Usable capacity in bytes
 */
static size_t get_payload_capacity(Header *hdr)
{
    uint8_t *payload = (uint8_t *)get_aligned_payload(hdr);
    uint8_t *footer_start = (uint8_t *)get_block_footer(hdr);

    if (payload >= footer_start) {
        return 0;
    }

    return (size_t)(footer_start - payload);
}

/**
 * @brief Gets the free list links from a free block.
 *
 * @param hdr Pointer to the block header
 * @return Pointer to the free links structure
 */
static FreeLinks *get_free_links(Header *hdr)
{
    return (FreeLinks *)get_data_area(hdr);
}

/*===========================================================================*/
/*                      QUARANTINE FUNCTIONS                                  */
/*===========================================================================*/

/**
 * @brief Checks if a block is quarantined.
 *
 * @param ptr Pointer to check
 * @return true if the block is quarantined, false otherwise
 */
static bool is_quarantined(const void *ptr)
{
    size_t i;

    for (i = 0; i < quarantine_count; i++) {
        if (quarantine_list[i] == ptr) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Adds a block to the quarantine list.
 *
 * Quarantined blocks are never reused or merged.
 *
 * @param ptr Pointer to the corrupted block
 */
static void quarantine_block(void *ptr)
{
    if (ptr == NULL || is_quarantined(ptr)) {
        return;
    }

    if (quarantine_count < MAX_QUARANTINE) {
        quarantine_list[quarantine_count] = ptr;
        quarantine_count++;
    }

    stats_corruption_count++;
}

/*===========================================================================*/
/*                      VALIDATION FUNCTIONS                                  */
/*===========================================================================*/

/**
 * @brief Validates a block header for corruption.
 *
 * Checks magic number, size consistency, bounds, and checksum.
 *
 * @param hdr Pointer to the header to validate
 * @return true if header is valid, false if corrupted
 */
static bool validate_header(Header *hdr)
{
    /* Check pointer is within heap bounds */
    if (!is_within_heap(hdr)) {
        return false;
    }

    /* Check header fits within heap */
    if ((uint8_t *)hdr + sizeof(Header) > heap_end) {
        return false;
    }

    /* Check magic number */
    if (hdr->magic != HEADER_MAGIC) {
        return false;
    }

    /* Check size is reasonable */
    if (hdr->size < sizeof(Header) + sizeof(Footer)) {
        return false;
    }

    if (hdr->size > heap_total_size) {
        return false;
    }

    /* Check redundant size matches */
    if (hdr->size != hdr->size_backup) {
        return false;
    }

    /* Check block fits within heap */
    if ((uint8_t *)hdr + hdr->size > heap_end) {
        return false;
    }

    /* Verify checksum */
    if (hdr->checksum != compute_header_checksum(hdr)) {
        return false;
    }

    return true;
}

/**
 * @brief Validates a block footer for corruption.
 *
 * Checks magic number, size consistency with header, and checksum.
 *
 * @param hdr Pointer to the block header
 * @return true if footer is valid, false if corrupted
 */
static bool validate_footer(Header *hdr)
{
    Footer *ftr = get_block_footer(hdr);

    /* Check footer pointer is within heap */
    if (!is_within_heap(ftr)) {
        return false;
    }

    /* Check footer fits within heap */
    if ((uint8_t *)ftr + sizeof(Footer) > heap_end) {
        return false;
    }

    /* Check magic number */
    if (ftr->magic != FOOTER_MAGIC) {
        return false;
    }

    /* Check size matches header */
    if (ftr->size != hdr->size) {
        return false;
    }

    /* Check redundant size matches */
    if (ftr->size != ftr->size_backup) {
        return false;
    }

    /* Verify checksum */
    if (ftr->checksum != compute_footer_checksum(ftr)) {
        return false;
    }

    return true;
}

/**
 * @brief Validates an entire block (header and footer).
 *
 * @param hdr Pointer to the block header
 * @return true if block is valid, false if corrupted
 */
static bool validate_block(Header *hdr)
{
    return validate_header(hdr) && validate_footer(hdr);
}

/**
 * @brief Checks for brownout condition (interrupted write).
 *
 * A brownout is detected when the write state indicates a write
 * was in progress but never completed.
 *
 * @param hdr Pointer to the block header
 * @return true if brownout detected, false otherwise
 */
static bool detect_brownout(Header *hdr)
{
    return (hdr->write_state == STATE_WRITING);
}

/*===========================================================================*/
/*                      BLOCK INITIALIZATION                                  */
/*===========================================================================*/

/**
 * @brief Initializes a block header with the specified parameters.
 *
 * Sets all header fields and computes the checksum.
 *
 * @param hdr         Pointer to the header
 * @param block_size  Total block size
 * @param allocated   Allocation status (1 or 0)
 * @param write_state Write state for brownout detection
 */
static void init_header(Header *hdr, size_t block_size, uint32_t allocated,
                        uint32_t write_state)
{
    hdr->magic = HEADER_MAGIC;
    hdr->size = block_size;
    hdr->size_backup = block_size;
    hdr->is_alloc = allocated;
    hdr->write_state = write_state;
    hdr->checksum = compute_header_checksum(hdr);
}

/**
 * @brief Initializes a block footer based on header information.
 *
 * Sets all footer fields and computes the checksum.
 *
 * @param hdr Pointer to the block header
 */
static void init_footer(Header *hdr)
{
    Footer *ftr = get_block_footer(hdr);

    ftr->magic = FOOTER_MAGIC;
    ftr->size = hdr->size;
    ftr->size_backup = hdr->size;
    ftr->checksum = compute_footer_checksum(ftr);
}

/*===========================================================================*/
/*                      FREE LIST MANAGEMENT                                  */
/*===========================================================================*/

/**
 * @brief Removes a block from the free list.
 *
 * Updates the prev/next pointers of adjacent nodes.
 *
 * @param hdr Pointer to the block header to remove
 */
static void free_list_remove(Header *hdr)
{
    FreeLinks *links = get_free_links(hdr);

    if (links->prev != NULL) {
        links->prev->next = links->next;
    } else {
        free_list_head = links->next;
    }

    if (links->next != NULL) {
        links->next->prev = links->prev;
    }
}

/**
 * @brief Adds a block to the front of the free list.
 *
 * @param hdr Pointer to the block header to add
 */
static void free_list_add(Header *hdr)
{
    FreeLinks *links = get_free_links(hdr);

    links->next = free_list_head;
    links->prev = NULL;

    if (free_list_head != NULL) {
        free_list_head->prev = links;
    }

    free_list_head = links;
}

/*===========================================================================*/
/*                      BLOCK SEARCH FUNCTIONS                                */
/*===========================================================================*/

/**
 * @brief Finds the header for a given payload pointer.
 *
 * Scans the heap linearly to find the block containing the payload.
 *
 * @param payload Pointer to the payload area
 * @return Pointer to the header, or NULL if not found
 */
static Header *find_block_header(void *payload)
{
    uint8_t *scan;
    size_t min_block_size;

    if (payload == NULL || !is_initialized) {
        return NULL;
    }

    if (!is_within_heap(payload)) {
        return NULL;
    }

    scan = heap_start;
    min_block_size = sizeof(Header) + sizeof(Footer);

    while (scan + min_block_size <= heap_end) {
        Header *hdr = (Header *)scan;

        /* Check if this looks like a valid header */
        if (hdr->magic == HEADER_MAGIC &&
            hdr->size >= min_block_size &&
            hdr->size <= heap_total_size &&
            scan + hdr->size <= heap_end) {

            /* Check if payload matches */
            if (get_aligned_payload(hdr) == payload) {
                return hdr;
            }

            /* Move to next block */
            scan += hdr->size;
        } else {
            /* Invalid header, skip ahead */
            scan += 8;
        }
    }

    return NULL;
}

/**
 * @brief Finds a free block of at least the specified size.
 *
 * Uses first-fit strategy. Removes corrupted blocks from the list.
 *
 * @param min_size Minimum required block size
 * @return Pointer to a suitable header, or NULL if none found
 */
static Header *find_free_block(size_t min_size)
{
    FreeLinks *current = free_list_head;
    FreeLinks *prev_link = NULL;

    while (current != NULL) {
        Header *hdr;
        FreeLinks *next;

        /* Check if pointer is valid */
        if (!is_within_heap(current)) {
            /* Corrupted pointer - truncate list */
            if (prev_link != NULL) {
                prev_link->next = NULL;
            } else {
                free_list_head = NULL;
            }
            quarantine_block(current);
            break;
        }

        hdr = (Header *)((uint8_t *)current - sizeof(Header));

        /* Check if block is quarantined */
        if (is_quarantined(hdr)) {
            next = current->next;
            if (prev_link != NULL) {
                prev_link->next = next;
            } else {
                free_list_head = next;
            }
            if (next != NULL && is_within_heap(next)) {
                next->prev = prev_link;
            }
            current = next;
            continue;
        }

        /* Validate block integrity */
        if (!validate_block(hdr)) {
            /* Remove corrupted block from list */
            quarantine_block(hdr);
            next = current->next;

            if (prev_link != NULL) {
                prev_link->next = next;
            } else {
                free_list_head = next;
            }

            if (next != NULL && is_within_heap(next)) {
                next->prev = prev_link;
            }

            current = next;
            continue;
        }

        /* Check if block is free and large enough */
        if (hdr->is_alloc == 0 && hdr->size >= min_size) {
            return hdr;
        }

        prev_link = current;
        current = current->next;
    }

    return NULL;
}

/*===========================================================================*/
/*                      BLOCK SPLITTING AND COALESCING                        */
/*===========================================================================*/

/**
 * @brief Splits a block if the remainder is large enough.
 *
 * Creates a new free block from excess space.
 *
 * @param hdr    Pointer to the block header
 * @param needed Required size for the first block
 */
static void split_block(Header *hdr, size_t needed)
{
    size_t min_remainder;
    size_t new_block_size;
    Header *new_hdr;
    uint8_t *data;
    size_t data_len;

    min_remainder = sizeof(Header) + MIN_DATA_SIZE + sizeof(Footer);

    /* Only split if remainder can form a valid block */
    if (hdr->size < needed + min_remainder) {
        return;
    }

    new_block_size = hdr->size - needed;

    /* Shrink original block */
    init_header(hdr, needed, hdr->is_alloc, hdr->write_state);
    init_footer(hdr);

    /* Create new free block from remainder */
    new_hdr = (Header *)((uint8_t *)hdr + needed);
    init_header(new_hdr, new_block_size, 0, STATE_WRITTEN);
    init_footer(new_hdr);

    /* Fill new block's data with free pattern */
    data = get_data_area(new_hdr);
    data_len = new_block_size - sizeof(Header) - sizeof(Footer);

    if (data_len > sizeof(FreeLinks)) {
        fill_free_pattern(data + sizeof(FreeLinks),
                          data_len - sizeof(FreeLinks));
    }

    /* Add new block to free list */
    free_list_add(new_hdr);
}

/**
 * @brief Coalesces adjacent free blocks.
 *
 * Scans the heap linearly and merges consecutive free blocks.
 */
static void coalesce_free_blocks(void)
{
    uint8_t *scan;
    size_t min_block_size;

    scan = heap_start;
    min_block_size = sizeof(Header) + sizeof(Footer);

    while (scan + min_block_size < heap_end) {
        Header *hdr = (Header *)scan;
        Header *next_hdr;
        uint8_t *next_addr;

        /* Skip if not a valid header */
        if (hdr->magic != HEADER_MAGIC ||
            hdr->size < min_block_size ||
            hdr->size > heap_total_size ||
            scan + hdr->size > heap_end) {
            scan += 8;
            continue;
        }

        /* Skip if block is corrupted or quarantined */
        if (!validate_block(hdr) || is_quarantined(hdr)) {
            scan += 8;
            continue;
        }

        /* Check next block */
        next_addr = scan + hdr->size;
        if (next_addr + min_block_size > heap_end) {
            break;
        }

        next_hdr = (Header *)next_addr;

        /* Skip if next block is invalid or quarantined */
        if (next_hdr->magic != HEADER_MAGIC ||
            !validate_block(next_hdr) ||
            is_quarantined(next_hdr)) {
            scan = next_addr;
            continue;
        }

        /* Merge if both blocks are free */
        if (hdr->is_alloc == 0 && next_hdr->is_alloc == 0) {
            size_t combined_size;
            uint8_t *data;
            size_t data_len;

            /* Remove both from free list */
            free_list_remove(hdr);
            free_list_remove(next_hdr);

            /* Create merged block */
            combined_size = hdr->size + next_hdr->size;
            init_header(hdr, combined_size, 0, STATE_WRITTEN);
            init_footer(hdr);

            /* Fill data area with free pattern */
            data = get_data_area(hdr);
            data_len = combined_size - sizeof(Header) - sizeof(Footer);

            if (data_len > sizeof(FreeLinks)) {
                fill_free_pattern(data + sizeof(FreeLinks),
                                  data_len - sizeof(FreeLinks));
            }

            /* Add merged block to free list */
            free_list_add(hdr);

            /* Continue without advancing to check for more merges */
            continue;
        }

        scan = next_addr;
    }
}

/*===========================================================================*/
/*                      PUBLIC API FUNCTIONS                                  */
/*===========================================================================*/

/**
 * @brief Initializes the memory allocator.
 *
 * Sets up the heap with a single free block and fills all unused
 * memory with the 5-byte identification pattern.
 *
 * @param heap      Pointer to the memory block to manage
 * @param heap_size Size of the memory block in bytes
 * @return 0 on success, -1 on failure
 */
int mm_init(uint8_t *heap, size_t heap_size)
{
    Header *initial_block;
    size_t block_size;
    FreeLinks *links;
    uint8_t *data;
    size_t data_len;
    size_t i;

    /* Validate input parameters */
    if (heap == NULL) {
        return -1;
    }

    if (heap_size < MIN_HEAP_SIZE) {
        return -1;
    }

    /* Initialize global state */
    heap_start = heap;
    heap_end = heap + heap_size;
    heap_total_size = heap_size;
    free_list_head = NULL;
    is_initialized = true;
    stats_allocated_bytes = 0;
    stats_corruption_count = 0;

    /* Clear quarantine list */
    quarantine_count = 0;
    for (i = 0; i < MAX_QUARANTINE; i++) {
        quarantine_list[i] = NULL;
    }

    /* Fill entire heap with free pattern first */
    fill_free_pattern(heap, heap_size);

    /* Create initial free block spanning entire heap */
    initial_block = (Header *)heap;
    block_size = (heap_size / 8) * 8;  /* Align to 8 bytes */

    init_header(initial_block, block_size, 0, STATE_WRITTEN);
    init_footer(initial_block);

    /* Initialize free list with this block */
    links = get_free_links(initial_block);
    links->next = NULL;
    links->prev = NULL;
    free_list_head = links;

    /* Fill data area with pattern (preserve FreeLinks) */
    data = get_data_area(initial_block);
    data_len = block_size - sizeof(Header) - sizeof(Footer);

    if (data_len > sizeof(FreeLinks)) {
        fill_free_pattern(data + sizeof(FreeLinks),
                          data_len - sizeof(FreeLinks));
    }

    return 0;
}

/**
 * @brief Allocates a block of memory.
 *
 * Returns a 40-byte aligned pointer to a payload area of at least
 * the requested size.
 *
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void *mm_malloc(size_t size)
{
    size_t data_needed;
    size_t block_size;
    size_t min_block;
    Header *hdr;
    void *payload;
    size_t capacity;
    size_t base_offset;
    size_t i;

    /* Check initialization and size */
    if (!is_initialized) {
        return NULL;
    }

    if (size == 0) {
        return NULL;
    }

    /* Calculate required block size */
    data_needed = size + ALIGNMENT;  /* Extra space for alignment padding */
    block_size = sizeof(Header) + data_needed + sizeof(Footer);
    block_size = align_up(block_size, 8);

    /* Ensure minimum block size */
    min_block = sizeof(Header) + MIN_DATA_SIZE + sizeof(Footer);
    if (block_size < min_block) {
        block_size = min_block;
    }

    /* Find a suitable free block */
    hdr = find_free_block(block_size);

    if (hdr == NULL) {
        /* Try coalescing and search again */
        coalesce_free_blocks();
        hdr = find_free_block(block_size);
    }

    if (hdr == NULL) {
        return NULL;
    }

    /* Remove from free list and split if possible */
    free_list_remove(hdr);
    split_block(hdr, block_size);

    /* Mark as allocated with UNWRITTEN state for brownout detection */
    init_header(hdr, hdr->size, 1, STATE_UNWRITTEN);
    init_footer(hdr);

    /* Update statistics */
    stats_allocated_bytes += hdr->size;

    /* Get payload and fill with free pattern for clean state */
    payload = get_aligned_payload(hdr);
    capacity = get_payload_capacity(hdr);
    base_offset = (size_t)((uint8_t *)payload - heap_start);

    for (i = 0; i < capacity; i++) {
        ((uint8_t *)payload)[i] = FREE_PATTERN[(base_offset + i) % 5];
    }

    return payload;
}

/**
 * @brief Reads data from an allocated block.
 *
 * Performs corruption and brownout detection before reading.
 *
 * @param ptr    Pointer to the allocated block's payload
 * @param offset Byte offset within the payload
 * @param buf    Buffer to store read data
 * @param len    Number of bytes to read
 * @return Number of bytes read, or -1 on error
 */
int mm_read(void *ptr, size_t offset, void *buf, size_t len)
{
    Header *hdr;
    size_t capacity;

    /* Validate parameters */
    if (ptr == NULL || buf == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    /* Find and validate block */
    hdr = find_block_header(ptr);
    if (hdr == NULL) {
        return -1;
    }

    /* Check if block is quarantined */
    if (is_quarantined(hdr)) {
        return -1;
    }

    /* Validate block integrity */
    if (!validate_block(hdr)) {
        quarantine_block(hdr);
        return -1;
    }

    /* Check allocation status */
    if (hdr->is_alloc == 0) {
        return -1;
    }

    /* Brownout detection: check for interrupted write */
    if (detect_brownout(hdr)) {
        quarantine_block(hdr);
        return -1;
    }

    /* Bounds check */
    capacity = get_payload_capacity(hdr);
    if (offset >= capacity) {
        return -1;
    }

    if (len > capacity - offset) {
        return -1;
    }

    /* Perform the read */
    memcpy(buf, (uint8_t *)ptr + offset, len);

    return (int)len;
}

/**
 * @brief Writes data to an allocated block.
 *
 * Uses three-state commit protocol for brownout detection.
 *
 * @param ptr    Pointer to the allocated block's payload
 * @param offset Byte offset within the payload
 * @param src    Source data to write
 * @param len    Number of bytes to write
 * @return Number of bytes written, or -1 on error
 */
int mm_write(void *ptr, size_t offset, const void *src, size_t len)
{
    Header *hdr;
    size_t capacity;

    /* Validate parameters */
    if (ptr == NULL || src == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    /* Find and validate block */
    hdr = find_block_header(ptr);
    if (hdr == NULL) {
        return -1;
    }

    /* Check if block is quarantined */
    if (is_quarantined(hdr)) {
        return -1;
    }

    /* Validate block integrity */
    if (!validate_block(hdr)) {
        quarantine_block(hdr);
        return -1;
    }

    /* Check allocation status */
    if (hdr->is_alloc == 0) {
        return -1;
    }

    /* Bounds check */
    capacity = get_payload_capacity(hdr);
    if (offset >= capacity) {
        return -1;
    }

    if (len > capacity - offset) {
        return -1;
    }

    /* Three-state commit protocol for brownout detection */
    /* Step 1: Set WRITING state before memcpy */
    hdr->write_state = STATE_WRITING;
    hdr->checksum = compute_header_checksum(hdr);

    /* Step 2: Perform the actual write */
    memcpy((uint8_t *)ptr + offset, src, len);

    /* Step 3: Set WRITTEN state after memcpy completes */
    hdr->write_state = STATE_WRITTEN;
    hdr->checksum = compute_header_checksum(hdr);

    return (int)len;
}

/**
 * @brief Frees an allocated block.
 *
 * Returns the block to the free list and coalesces with neighbors.
 * Handles NULL pointers and double-free safely.
 *
 * @param ptr Pointer to the allocated block's payload
 */
void mm_free(void *ptr)
{
    Header *hdr;
    uint8_t *data;
    size_t data_len;

    /* Handle NULL pointer */
    if (ptr == NULL) {
        return;
    }

    /* Find and validate block */
    hdr = find_block_header(ptr);
    if (hdr == NULL) {
        return;
    }

    /* Check if block is quarantined */
    if (is_quarantined(hdr)) {
        return;
    }

    /* Validate block integrity */
    if (!validate_block(hdr)) {
        quarantine_block(hdr);
        return;
    }

    /* Double-free detection */
    if (hdr->is_alloc == 0) {
        return;
    }

    /* Update statistics */
    stats_allocated_bytes -= hdr->size;

    /* Mark block as free */
    init_header(hdr, hdr->size, 0, STATE_WRITTEN);
    init_footer(hdr);

    /* Add to free list */
    free_list_add(hdr);

    /* Reset data area to free pattern */
    data = get_data_area(hdr);
    data_len = hdr->size - sizeof(Header) - sizeof(Footer);

    if (data_len > sizeof(FreeLinks)) {
        fill_free_pattern(data + sizeof(FreeLinks),
                          data_len - sizeof(FreeLinks));
    }

    /* Coalesce with adjacent free blocks */
    coalesce_free_blocks();
}

/**
 * @brief Resizes an allocated block.
 *
 * If new size fits in current block, returns same pointer.
 * Otherwise allocates new block, copies data, and frees old.
 *
 * @param ptr      Pointer to the existing allocation
 * @param new_size New size in bytes
 * @return Pointer to resized block, or NULL on failure
 */
void *mm_realloc(void *ptr, size_t new_size)
{
    Header *hdr;
    Header *new_hdr;
    size_t old_capacity;
    size_t copy_size;
    void *new_ptr;

    /* Handle NULL pointer (equivalent to malloc) */
    if (ptr == NULL) {
        return mm_malloc(new_size);
    }

    /* Handle zero size (equivalent to free) */
    if (new_size == 0) {
        mm_free(ptr);
        return NULL;
    }

    /* Find and validate block */
    hdr = find_block_header(ptr);
    if (hdr == NULL) {
        return NULL;
    }

    /* Check if block is quarantined */
    if (is_quarantined(hdr)) {
        return NULL;
    }

    /* Validate block integrity */
    if (!validate_block(hdr)) {
        quarantine_block(hdr);
        return NULL;
    }

    /* Check if current block is large enough */
    old_capacity = get_payload_capacity(hdr);
    if (new_size <= old_capacity) {
        return ptr;
    }

    /* Allocate new block */
    new_ptr = mm_malloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }

    /* Copy data from old block */
    copy_size = (old_capacity < new_size) ? old_capacity : new_size;
    memcpy(new_ptr, ptr, copy_size);

    /* Mark new block as written since data was copied */
    new_hdr = find_block_header(new_ptr);
    if (new_hdr != NULL && new_hdr->write_state != STATE_WRITTEN) {
        new_hdr->write_state = STATE_WRITTEN;
        new_hdr->checksum = compute_header_checksum(new_hdr);
    }

    /* Free old block */
    mm_free(ptr);

    return new_ptr;
}

/**
 * @brief Prints heap statistics for debugging.
 *
 * Outputs current allocation state, corruption count, and free list info.
 */
void mm_heap_stats(void)
{
    FreeLinks *current;
    size_t free_block_count = 0;
    size_t free_bytes = 0;

    printf("\n=== Heap Statistics ===\n");
    printf("Heap: %p - %p (%zu bytes)\n",
           (void *)heap_start, (void *)heap_end, heap_total_size);
    printf("Allocated: %zu bytes\n", stats_allocated_bytes);
    printf("Corruptions detected: %zu\n", stats_corruption_count);
    printf("Quarantined blocks: %zu\n", quarantine_count);

    /* Count free blocks */
    current = free_list_head;

    while (current != NULL && is_within_heap(current) &&
           free_block_count < 10000) {
        Header *hdr = (Header *)((uint8_t *)current - sizeof(Header));

        if (validate_block(hdr) && !is_quarantined(hdr)) {
            free_block_count++;
            free_bytes += hdr->size;
        }

        current = current->next;
    }

    printf("Free blocks: %zu (%zu bytes)\n", free_block_count, free_bytes);
    printf("=======================\n");
}
