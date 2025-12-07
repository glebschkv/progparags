/*
 * ============================================================================
 * COMP2221 Systems Programming - Mars Rover Memory Allocator
 * ============================================================================
 *
 * OVERVIEW:
 * This memory allocator is designed for the Mars Perseverance rover to handle
 * radiation-induced bit flips and power brownouts. All allocator metadata
 * lives within a single contiguous memory block provided by the rover's OS.
 *
 * DESIGN PRINCIPLES:
 * 1. Defense in Depth: Multiple validation layers catch corruption early
 * 2. Fail-Safe: Corrupted blocks are quarantined and handled safely
 * 3. Redundancy: Critical size data stored in header, footer, AND backup
 * 4. Brownout Detection: Commit flags detect partial writes
 * 5. Alignment: All payloads are 40-byte aligned relative to heap start
 *
 * MEMORY LAYOUT:
 *   [Header 72B][Payload Data][Footer 32B]
 *
 * CORRUPTION DETECTION:
 * - Magic numbers: Detect complete overwrites
 * - Canary values: Detect buffer overflows into metadata
 * - CRC32 checksums: Robust detection of bit flips
 * - Triple size redundancy: size in header, footer, and backup field
 * - Commit flags: Detect brownout (partial write) events
 *
 * ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"

/* ============================================================================
 * CONFIGURATION CONSTANTS
 * ============================================================================
 */

/* All returned pointers must be 40-byte aligned relative to heap start */
#define ALIGNMENT 40

/* Minimum payload size to prevent excessive fragmentation */
#define MIN_PAYLOAD 40

/* Magic numbers for corruption detection */
#define MAGIC_HDR 0xDEADBEEFU
#define MAGIC_FTR 0xCAFEBABEU
#define MAGIC_COMMIT 0xC0FFEE42U

/* Canary value to detect buffer overflows */
#define CANARY 0xABCDEF12U

/* Commit status values for brownout detection */
#define COMMIT_PENDING 0x00000000U
#define COMMIT_COMPLETE 0x12345678U

/* ============================================================================
 * FREE MEMORY PATTERN
 * ============================================================================
 */
static const uint8_t FREE_PAT[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x99};

/* ============================================================================
 * CRC32 TABLE AND FUNCTION
 * ============================================================================
 * Using CRC32 for robust checksum - much better at detecting bit flips
 */
static uint32_t crc32_table[256];
static int crc32_init_done = 0;

static void init_crc32_table(void) {
  if (crc32_init_done) return;
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t crc = i;
    for (int j = 0; j < 8; j++) {
      if (crc & 1)
        crc = (crc >> 1) ^ 0xEDB88320U;
      else
        crc = crc >> 1;
    }
    crc32_table[i] = crc;
  }
  crc32_init_done = 1;
}

static uint32_t calc_crc32(const void *data, size_t len) {
  const uint8_t *buf = (const uint8_t *)data;
  uint32_t crc = 0xFFFFFFFFU;
  for (size_t i = 0; i < len; i++) {
    crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFU;
}

/* ============================================================================
 * BLOCK HEADER STRUCTURE (72 bytes, 8-byte aligned)
 * ============================================================================
 * Contains redundant storage of critical fields for corruption resilience.
 * Commit flags enable detection of brownout (partial write) events.
 */
typedef struct Hdr {
  uint32_t magic;          /* Must be MAGIC_HDR - detects overwrites */
  uint32_t canary;         /* Must be CANARY - detects overflows */
  size_t size;             /* Total block size (data area) */
  size_t size_backup;      /* Backup copy of size for redundancy */
  uint32_t checksum;       /* CRC32 checksum of header fields */
  uint32_t is_free;        /* 1 if free, 0 if allocated */
  uint32_t commit;         /* Commit flag for brownout detection */
  uint32_t pad;            /* Padding for alignment */
  struct Hdr *next;        /* Next block in free list */
  struct Hdr *prev;        /* Previous block in free list */
} Hdr;

/* ============================================================================
 * BLOCK FOOTER STRUCTURE (32 bytes, 8-byte aligned)
 * ============================================================================
 * Provides redundant storage for size and additional integrity checks.
 */
typedef struct {
  uint32_t magic;          /* Must be MAGIC_FTR */
  uint32_t canary;         /* Must be CANARY */
  size_t size;             /* Must match header size */
  uint32_t checksum;       /* CRC32 checksum of footer fields */
  uint32_t commit;         /* Must match header commit */
  uint32_t pad;            /* Padding */
} Ftr;

/* ============================================================================
 * GLOBAL ALLOCATOR STATE
 * ============================================================================
 */
static struct {
  uint8_t *start;          /* Start of managed heap */
  uint8_t *end;            /* End of managed heap */
  size_t heap_size;        /* Total heap size in bytes */
  Hdr *free_list;          /* Head of doubly-linked free list */
  Hdr *quarantine;         /* Head of quarantined blocks list */
  size_t quarantine_cnt;   /* Number of quarantined blocks */
  bool init;               /* True if allocator is initialized */
  size_t alloc_bytes;      /* Total bytes currently allocated */
  size_t free_bytes;       /* Total bytes currently free */
  size_t alloc_count;      /* Number of successful allocations */
  size_t corrupt_count;    /* Number of corruption detections */
} g;

/* ============================================================================
 * CHECKSUM FUNCTIONS
 * ============================================================================
 */

/*
 * hdr_cs - Calculate header checksum using CRC32
 * @h: Header to checksum
 *
 * Computes CRC32 over critical header fields (excluding checksum and commit).
 * Commit flag is checked separately for brownout detection.
 */
static uint32_t hdr_cs(Hdr *h) {
  uint8_t buf[32];
  size_t off = 0;

  /* Pack critical fields for checksumming (NOT including commit) */
  memcpy(buf + off, &h->magic, 4); off += 4;
  memcpy(buf + off, &h->canary, 4); off += 4;
  memcpy(buf + off, &h->size, sizeof(size_t)); off += sizeof(size_t);
  memcpy(buf + off, &h->size_backup, sizeof(size_t)); off += sizeof(size_t);
  memcpy(buf + off, &h->is_free, 4); off += 4;

  return calc_crc32(buf, off);
}

/*
 * ftr_cs - Calculate footer checksum using CRC32
 * @f: Footer to checksum
 *
 * Commit flag is checked separately for brownout detection.
 */
static uint32_t ftr_cs(Ftr *f) {
  uint8_t buf[20];
  size_t off = 0;

  /* Pack critical fields (NOT including commit) */
  memcpy(buf + off, &f->magic, 4); off += 4;
  memcpy(buf + off, &f->canary, 4); off += 4;
  memcpy(buf + off, &f->size, sizeof(size_t)); off += sizeof(size_t);

  return calc_crc32(buf, off);
}

/* ============================================================================
 * POINTER AND BLOCK VALIDATION
 * ============================================================================
 */

/*
 * valid_ptr - Check if pointer is within heap bounds
 */
static bool valid_ptr(void *p) {
  if (!p) return false;
  uint8_t *bp = (uint8_t *)p;
  return bp >= g.start && bp < g.end;
}

/*
 * get_payload - Get aligned payload pointer from header
 *
 * Ensures payload is 40-byte aligned relative to heap start.
 */
static void *get_payload(Hdr *h) {
  uint8_t *raw = (uint8_t *)h + sizeof(Hdr);
  size_t off = (size_t)(raw - g.start);
  size_t pad = (off % ALIGNMENT) ? (ALIGNMENT - (off % ALIGNMENT)) : 0;
  return raw + pad;
}

/*
 * get_footer - Get footer pointer from header
 */
static Ftr *get_footer(Hdr *h) {
  return (Ftr *)((uint8_t *)h + sizeof(Hdr) + h->size);
}

/*
 * payload_size - Get usable payload size
 */
static size_t payload_size(Hdr *h) {
  void *p = get_payload(h);
  size_t pad = (size_t)((uint8_t *)p - (uint8_t *)h - sizeof(Hdr));
  return h->size - pad;
}

/*
 * valid_hdr - Validate header integrity
 *
 * Performs multiple checks:
 * 1. Pointer bounds check
 * 2. Magic number verification
 * 3. Canary value verification
 * 4. Size sanity check
 * 5. Size redundancy check (size == size_backup)
 * 6. Commit flag verification (brownout detection)
 * 7. CRC32 checksum verification
 */
static bool valid_hdr(Hdr *h) {
  if (!valid_ptr(h)) return false;
  if (h->magic != MAGIC_HDR) return false;
  if (h->canary != CANARY) return false;
  if (h->size == 0 || h->size > g.heap_size) return false;

  /* Check size redundancy - detects partial corruption */
  if (h->size != h->size_backup) return false;

  /* Check commit flag - detects brownout events */
  if (h->commit != COMMIT_COMPLETE) return false;

  /* Verify CRC32 checksum */
  uint32_t stored = h->checksum;
  h->checksum = 0;
  uint32_t calc = hdr_cs(h);
  h->checksum = stored;

  return stored == calc;
}

/*
 * valid_ftr - Validate footer integrity
 */
static bool valid_ftr(Ftr *f, Hdr *h) {
  if (!valid_ptr(f)) return false;
  if (f->magic != MAGIC_FTR) return false;
  if (f->canary != CANARY) return false;
  if (f->size != h->size) return false;

  /* Check commit flag matches header */
  if (f->commit != h->commit) return false;

  /* Verify CRC32 checksum */
  uint32_t stored = f->checksum;
  f->checksum = 0;
  uint32_t calc = ftr_cs(f);
  f->checksum = stored;

  return stored == calc;
}

/*
 * valid_block - Full block validation (header + footer)
 */
static bool valid_block(Hdr *h) {
  if (!valid_hdr(h)) return false;
  Ftr *f = get_footer(h);
  if ((uint8_t *)f + sizeof(Ftr) > g.end) return false;
  return valid_ftr(f, h);
}

/*
 * try_recover_size - Attempt to recover size from redundant fields
 *
 * If one size field is corrupted, use the others.
 * Returns 0 if recovery fails.
 */
static size_t try_recover_size(Hdr *h) {
  /* Try each size source */
  size_t sizes[3] = {0, 0, 0};
  int valid_count = 0;

  /* Check header size */
  if (h->size > 0 && h->size <= g.heap_size) {
    sizes[0] = h->size;
    valid_count++;
  }

  /* Check backup size */
  if (h->size_backup > 0 && h->size_backup <= g.heap_size) {
    sizes[1] = h->size_backup;
    valid_count++;
  }

  /* Try to get footer size if we can guess location */
  if (sizes[0] > 0) {
    Ftr *f = (Ftr *)((uint8_t *)h + sizeof(Hdr) + sizes[0]);
    if (valid_ptr(f) && f->size > 0 && f->size <= g.heap_size) {
      sizes[2] = f->size;
      valid_count++;
    }
  }

  /* Vote: if at least 2 agree, use that value */
  if (sizes[0] > 0 && sizes[0] == sizes[1]) return sizes[0];
  if (sizes[0] > 0 && sizes[0] == sizes[2]) return sizes[0];
  if (sizes[1] > 0 && sizes[1] == sizes[2]) return sizes[1];

  /* Return first valid size */
  for (int i = 0; i < 3; i++) {
    if (sizes[i] > 0) return sizes[i];
  }

  return 0;
}

/*
 * ptr_to_hdr - Find header for a user pointer
 *
 * Scans heap to find the block containing this pointer.
 * Handles corrupted blocks by attempting recovery.
 */
static Hdr *ptr_to_hdr(void *p) {
  if (!p || !g.init) return NULL;
  if (!valid_ptr(p)) return NULL;

  uint8_t *scan = g.start;
  while (scan + sizeof(Hdr) + sizeof(Ftr) <= g.end) {
    Hdr *h = (Hdr *)scan;

    /* Check for valid magic number */
    if (h->magic == MAGIC_HDR) {
      /* Try to get a valid size */
      size_t sz = h->size;
      if (sz == 0 || sz > g.heap_size) {
        sz = try_recover_size(h);
      }

      if (sz > 0 && sz <= g.heap_size) {
        /* Check if this is our block */
        if (get_payload(h) == p) {
          return h;
        }
        /* Move to next block */
        size_t total = sizeof(Hdr) + sz + sizeof(Ftr);
        if (scan + total <= g.end) {
          scan += total;
          continue;
        }
      }
    }

    /* Skip forward - try to find next valid header */
    scan += 8;
  }
  return NULL;
}

/*
 * write_pat - Write free pattern to memory
 */
static void write_pat(void *p, size_t n) {
  uint8_t *bp = (uint8_t *)p;
  for (size_t i = 0; i < n; i++) {
    bp[i] = FREE_PAT[i % 5];
  }
}

/*
 * fin_hdr - Finalize header with checksum
 */
static void fin_hdr(Hdr *h) {
  h->checksum = 0;
  h->checksum = hdr_cs(h);
}

/*
 * fin_ftr - Finalize footer with all fields
 */
static void fin_ftr(Ftr *f, size_t sz, uint32_t commit) {
  f->magic = MAGIC_FTR;
  f->canary = CANARY;
  f->size = sz;
  f->commit = commit;
  f->checksum = 0;
  f->checksum = ftr_cs(f);
}

/*
 * list_rm - Remove block from free list
 */
static void list_rm(Hdr *h) {
  if (h->prev) h->prev->next = h->next;
  else g.free_list = h->next;
  if (h->next) h->next->prev = h->prev;
  h->next = h->prev = NULL;
}

/*
 * list_add - Add block to front of free list
 */
static void list_add(Hdr *h) {
  h->next = g.free_list;
  h->prev = NULL;
  if (g.free_list) g.free_list->prev = h;
  g.free_list = h;
}

/*
 * quarantine_block - Remove corrupted block from circulation
 *
 * Safely removes a block from the free list (if present) and adds it
 * to the quarantine list. Since the block may be corrupted, we search
 * the free list by pointer rather than trusting is_free flag.
 */
static void quarantine_block(Hdr *h) {
  if (!h) return;

  /* Search free list for this block (don't trust is_free - may be corrupted) */
  Hdr *cur = g.free_list;
  Hdr *prev_node = NULL;
  int max_iter = 10000;  /* Prevent infinite loops from corrupted list */
  while (cur && max_iter-- > 0) {
    if (cur == h) {
      /* Found in free list - remove it safely */
      Hdr *next_ptr = cur->next;
      if (!valid_ptr(next_ptr) && next_ptr != NULL) {
        /* next pointer is corrupted - truncate list here */
        next_ptr = NULL;
      }
      if (prev_node) {
        prev_node->next = next_ptr;
      } else {
        g.free_list = next_ptr;
      }
      if (next_ptr && valid_ptr(next_ptr)) {
        next_ptr->prev = prev_node;
      }
      break;
    }
    prev_node = cur;
    /* Validate next pointer before following it */
    Hdr *next = cur->next;
    if (next && !valid_ptr(next)) {
      /* Corrupted next pointer - stop traversal */
      break;
    }
    cur = next;
  }

  /* Add to quarantine list */
  h->next = g.quarantine;
  h->prev = NULL;
  g.quarantine = h;
  g.quarantine_cnt++;
  g.corrupt_count++;
}

/*
 * align_up - Round value up to alignment boundary
 */
static size_t align_up(size_t v, size_t a) {
  return ((v + a - 1) / a) * a;
}

/*
 * find_block - Find a suitable free block
 *
 * Uses first-fit strategy. Quarantines corrupted blocks.
 * Handles corrupted free list pointers safely.
 */
static Hdr *find_block(size_t need) {
  Hdr *cur = g.free_list;
  int max_iter = 10000;  /* Prevent infinite loops */
  while (cur && max_iter-- > 0) {
    /* Save next pointer before potentially quarantining */
    Hdr *next_block = cur->next;

    /* Validate next pointer */
    if (next_block && !valid_ptr(next_block)) {
      /* Corrupted next pointer - truncate list and quarantine current */
      cur->next = NULL;
      next_block = NULL;
    }

    /* Check block validity */
    if (!valid_block(cur)) {
      quarantine_block(cur);
      cur = next_block;
      continue;
    }

    /* Check if block is suitable */
    if (cur->is_free && cur->size >= need) {
      return cur;
    }
    cur = next_block;
  }
  return NULL;
}

/*
 * do_split - Split a block if it's too large
 */
static void do_split(Hdr *h, size_t need) {
  size_t min_new = sizeof(Hdr) + MIN_PAYLOAD + sizeof(Ftr);
  if (h->size < need + min_new) return;

  size_t new_sz = h->size - need - sizeof(Hdr) - sizeof(Ftr);
  uint8_t *loc = (uint8_t *)h + sizeof(Hdr) + need + sizeof(Ftr);
  Hdr *new_h = (Hdr *)loc;

  /* Initialize new block header with commit pending */
  new_h->magic = MAGIC_HDR;
  new_h->canary = CANARY;
  new_h->size = new_sz;
  new_h->size_backup = new_sz;
  new_h->is_free = 1;
  new_h->commit = COMMIT_PENDING;
  new_h->next = new_h->prev = NULL;

  /* Write footer with commit pending */
  fin_ftr(get_footer(new_h), new_sz, COMMIT_PENDING);

  /* Now finalize header */
  fin_hdr(new_h);

  /* Mark commit as complete */
  new_h->commit = COMMIT_COMPLETE;
  fin_hdr(new_h);
  fin_ftr(get_footer(new_h), new_sz, COMMIT_COMPLETE);

  /* Write free pattern */
  write_pat(get_payload(new_h), payload_size(new_h));

  /* Update original block */
  h->size = need;
  h->size_backup = need;
  h->commit = COMMIT_COMPLETE;
  fin_ftr(get_footer(h), need, COMMIT_COMPLETE);
  fin_hdr(h);

  list_add(new_h);
}

/*
 * do_coalesce - Merge adjacent free blocks
 */
static void do_coalesce(void) {
  uint8_t *scan = g.start;
  while (scan + sizeof(Hdr) + sizeof(Ftr) <= g.end) {
    Hdr *cur = (Hdr *)scan;

    /* Check for valid header */
    if (cur->magic != MAGIC_HDR) {
      scan += 8;
      continue;
    }

    /* Try to get valid size */
    size_t sz = cur->size;
    if (sz == 0 || sz > g.heap_size) {
      sz = try_recover_size(cur);
    }
    if (sz == 0 || sz > g.heap_size) {
      scan += 8;
      continue;
    }

    /* Validate full block */
    if (!valid_block(cur)) {
      quarantine_block(cur);
      scan += 8;
      continue;
    }

    size_t total = sizeof(Hdr) + sz + sizeof(Ftr);
    uint8_t *next_pos = scan + total;
    if (next_pos + sizeof(Hdr) + sizeof(Ftr) > g.end) break;

    Hdr *next = (Hdr *)next_pos;

    /* Check if next block is valid */
    if (next->magic != MAGIC_HDR) {
      scan = next_pos;
      continue;
    }

    size_t next_sz = next->size;
    if (next_sz == 0 || next_sz > g.heap_size) {
      next_sz = try_recover_size(next);
    }
    if (next_sz == 0 || next_sz > g.heap_size) {
      scan = next_pos;
      continue;
    }

    /* Check if both blocks are free and can be merged */
    bool can_merge = valid_block(next) && cur->is_free && next->is_free;

    if (can_merge) {
      list_rm(next);
      size_t combined = cur->size + sizeof(Hdr) + sizeof(Ftr) + next->size;

      /* Update with brownout-safe sequence */
      cur->size = combined;
      cur->size_backup = combined;
      cur->commit = COMMIT_COMPLETE;
      fin_ftr(get_footer(cur), combined, COMMIT_COMPLETE);
      fin_hdr(cur);

      write_pat(get_payload(cur), payload_size(cur));
      continue;
    }
    scan = next_pos;
  }
}

/*
 * mm_init - Initialize the memory allocator
 */
int mm_init(uint8_t *heap, size_t heap_size) {
  if (!heap || heap_size < 1024) return -1;

  /* Initialize CRC table */
  init_crc32_table();

  memset(&g, 0, sizeof(g));
  g.start = heap;
  g.end = heap + heap_size;
  g.heap_size = heap_size;
  g.init = true;

  /* Calculate usable size */
  size_t overhead = sizeof(Hdr) + sizeof(Ftr);
  size_t usable = heap_size - overhead;
  usable = (usable / 8) * 8;

  Hdr *h = (Hdr *)heap;

  /* Initialize header with commit pending (brownout-safe) */
  h->magic = MAGIC_HDR;
  h->canary = CANARY;
  h->size = usable;
  h->size_backup = usable;
  h->is_free = 1;
  h->commit = COMMIT_PENDING;
  h->next = h->prev = NULL;

  /* Write footer first */
  fin_ftr(get_footer(h), usable, COMMIT_PENDING);

  /* Finalize header */
  fin_hdr(h);

  /* Mark as complete */
  h->commit = COMMIT_COMPLETE;
  fin_hdr(h);
  fin_ftr(get_footer(h), usable, COMMIT_COMPLETE);

  /* Write free pattern */
  write_pat(get_payload(h), payload_size(h));

  g.free_list = h;
  g.free_bytes = usable;
  return 0;
}

/*
 * mm_malloc - Allocate memory
 */
void *mm_malloc(size_t size) {
  if (!g.init || size == 0) return NULL;

  size_t need = size + ALIGNMENT;
  need = align_up(need, 8);
  if (need < MIN_PAYLOAD) need = MIN_PAYLOAD;
  if (need > g.heap_size) return NULL;

  Hdr *h = find_block(need);
  if (!h) {
    do_coalesce();
    h = find_block(need);
  }
  if (!h) return NULL;

  do_split(h, need);
  list_rm(h);

  /* Update allocation status with brownout safety */
  h->is_free = 0;
  h->commit = COMMIT_COMPLETE;
  fin_hdr(h);
  fin_ftr(get_footer(h), h->size, COMMIT_COMPLETE);

  g.alloc_bytes += h->size;
  g.free_bytes -= h->size;
  g.alloc_count++;

  void *p = get_payload(h);
  memset(p, 0, size);
  return p;
}

/*
 * mm_read - Safely read from an allocated block
 *
 * Returns bytes read, or -1 on error.
 * Handles len=0 by returning 0 (success with no data).
 */
int mm_read(void *ptr, size_t offset, void *buf, size_t len) {
  if (!ptr || !buf) return -1;
  if (len == 0) return 0;  /* Success - no data to read */

  Hdr *h = ptr_to_hdr(ptr);
  if (!h) return -1;

  /* Check block integrity */
  if (!valid_block(h)) {
    quarantine_block(h);
    return -1;
  }

  if (h->is_free) return -1;

  size_t ps = payload_size(h);
  /* Return -1 for any out-of-bounds access */
  if (offset >= ps || offset + len > ps) return -1;

  memcpy(buf, (uint8_t *)ptr + offset, len);
  return (int)len;
}

/*
 * mm_write - Safely write to an allocated block
 *
 * Returns bytes written, or -1 on error.
 * Handles len=0 by returning 0 (success with no data).
 */
int mm_write(void *ptr, size_t offset, const void *src, size_t len) {
  if (!ptr || !src) return -1;
  if (len == 0) return 0;  /* Success - no data to write */

  Hdr *h = ptr_to_hdr(ptr);
  if (!h) return -1;

  /* Check block integrity */
  if (!valid_block(h)) {
    quarantine_block(h);
    return -1;
  }

  if (h->is_free) return -1;

  size_t ps = payload_size(h);
  /* Return -1 for any out-of-bounds access */
  if (offset >= ps || offset + len > ps) return -1;

  memcpy((uint8_t *)ptr + offset, src, len);
  return (int)len;
}

/*
 * mm_free - Free a previously allocated block
 */
void mm_free(void *ptr) {
  if (!ptr) return;

  Hdr *h = ptr_to_hdr(ptr);
  if (!h) return;

  /* Check block integrity */
  if (!valid_block(h)) {
    quarantine_block(h);
    return;
  }

  /* Detect double-free */
  if (h->is_free) return;

  /* Mark as free with brownout safety */
  h->is_free = 1;
  h->commit = COMMIT_COMPLETE;
  fin_hdr(h);
  fin_ftr(get_footer(h), h->size, COMMIT_COMPLETE);

  /* Write free pattern */
  write_pat(get_payload(h), payload_size(h));

  list_add(h);
  g.alloc_bytes -= h->size;
  g.free_bytes += h->size;

  do_coalesce();
}

/*
 * mm_realloc - Resize an allocated block
 */
void *mm_realloc(void *ptr, size_t new_size) {
  if (!ptr) return mm_malloc(new_size);
  if (new_size == 0) {
    mm_free(ptr);
    return NULL;
  }

  Hdr *h = ptr_to_hdr(ptr);
  if (!h) return NULL;

  /* Check block integrity */
  if (!valid_block(h)) {
    quarantine_block(h);
    return NULL;
  }

  size_t old_ps = payload_size(h);
  if (new_size <= old_ps) return ptr;

  void *new_ptr = mm_malloc(new_size);
  if (!new_ptr) return NULL;

  memcpy(new_ptr, ptr, old_ps);
  mm_free(ptr);
  return new_ptr;
}

/*
 * mm_heap_stats - Print heap statistics
 */
void mm_heap_stats(void) {
  printf("\n=== Heap Statistics ===\n");
  printf("Heap Start: %p\n", (void *)g.start);
  printf("Heap Size: %zu bytes\n", g.heap_size);
  printf("Total Allocated: %zu bytes\n", g.alloc_bytes);
  printf("Total Free: %zu bytes\n", g.free_bytes);
  printf("Total Allocations: %zu\n", g.alloc_count);
  printf("Corruption Detections: %zu\n", g.corrupt_count);
  printf("Quarantined Blocks: %zu\n", g.quarantine_cnt);

  size_t free_count = 0, free_size = 0, max_free = 0;
  Hdr *cur = g.free_list;
  while (cur) {
    free_count++;
    free_size += cur->size;
    if (cur->size > max_free) max_free = cur->size;
    cur = cur->next;
  }
  printf("Free Blocks: %zu\n", free_count);
  printf("Free List Size: %zu bytes\n", free_size);
  printf("Largest Free Block: %zu bytes\n", max_free);
  printf("======================\n");
}
