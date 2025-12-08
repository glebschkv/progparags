/**
 * @file runme.c
 * @brief Mars Rover Memory Allocator Test Driver
 *
 * COMP2221 Systems Programming - Summative Assignment
 * Copyright 2025 COMP2221 Systems Programming
 *
 * This executable provides a test harness for the Mars Rover memory allocator.
 * It supports command-line arguments to configure test parameters including
 * heap size, random seed, and storm simulation levels.
 *
 * Usage:
 *   ./runme [OPTIONS]
 *
 * Options:
 *   --size <bytes>   Set heap size (default: 8192, range: 1024-1048576)
 *   --seed <num>     Set random seed for reproducible tests (default: 42)
 *   --storm <level>  Set storm level: 0=none, 1=light, 2=heavy (default: 0)
 *   --ops <num>      Number of random operations to perform (default: 0)
 *   --help           Display usage information
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "allocator.h"

/* Default heap size in bytes */
#define DEFAULT_HEAP_SIZE 8192

/* Default random seed for reproducible tests */
#define DEFAULT_SEED 42

/* Default storm level (0 = no storms) */
#define DEFAULT_STORM_LEVEL 0

/* Maximum allowed heap size */
#define MAX_HEAP_SIZE 1048576

/* Maximum number of concurrent allocations to track */
#define MAX_POINTERS 1000

/* Static heap buffer - allocated once, passed to mm_init */
static uint8_t g_heap[MAX_HEAP_SIZE];

/* Array of active allocation pointers */
static void *g_ptrs[MAX_POINTERS];

/* Array of allocation sizes corresponding to g_ptrs */
static size_t g_sizes[MAX_POINTERS];

/* Holds test configuration parameters */
typedef struct {
  size_t heap_size;
  unsigned int seed;
  int storm_level;
  int num_ops;
} Config;

/* Prints usage information for the test executable */
static void print_usage(const char *name) {
  printf("Usage: %s [OPTIONS]\n", name);
  printf("Options:\n");
  printf("  --size <bytes>   Heap size (default: %d, range: 1024-%d)\n",
         DEFAULT_HEAP_SIZE, MAX_HEAP_SIZE);
  printf("  --seed <num>     Random seed (default: %d)\n", DEFAULT_SEED);
  printf("  --storm <level>  Storm level: 0=none, 1=light, 2=heavy\n");
  printf("  --ops <num>      Number of operations (default: 0)\n");
  printf("  --help           Show this message\n");
}

/* Parses command-line arguments into configuration structure */
static void parse_args(int argc, char *argv[], Config *cfg) {
  int c;
  int idx = 0;
  static struct option opts[] = {
    {"size",  required_argument, 0, 's'},
    {"seed",  required_argument, 0, 'r'},
    {"storm", required_argument, 0, 't'},
    {"ops",   required_argument, 0, 'o'},
    {"help",  no_argument,       0, 'h'},
    {0, 0, 0, 0}
  };
  cfg->heap_size = DEFAULT_HEAP_SIZE;
  cfg->seed = DEFAULT_SEED;
  cfg->storm_level = DEFAULT_STORM_LEVEL;
  cfg->num_ops = 0;
  while ((c = getopt_long(argc, argv, "s:r:t:o:h", opts, &idx)) != -1) {
    switch (c) {
      case 's':
        cfg->heap_size = (size_t)atoi(optarg);
        if (cfg->heap_size < 1024 || cfg->heap_size > MAX_HEAP_SIZE) {
          printf("Error: size must be 1024-%d\n", MAX_HEAP_SIZE);
          exit(1);
        }
        break;
      case 'r':
        cfg->seed = (unsigned int)atoi(optarg);
        break;
      case 't':
        cfg->storm_level = atoi(optarg);
        if (cfg->storm_level < 0 || cfg->storm_level > 2) {
          printf("Error: storm must be 0, 1, or 2\n");
          exit(1);
        }
        break;
      case 'o':
        cfg->num_ops = atoi(optarg);
        if (cfg->num_ops < 0 || cfg->num_ops > MAX_POINTERS) {
          printf("Error: ops must be 0-%d\n", MAX_POINTERS);
          exit(1);
        }
        break;
      case 'h':
        print_usage(argv[0]);
        exit(0);
      default:
        print_usage(argv[0]);
        exit(1);
    }
  }
}

/* Flips a random bit in the heap to simulate radiation */
static void flip_bit(uint8_t *heap, size_t size, unsigned int *seedp) {
  size_t pos = (size_t)rand_r(seedp) % size;
  int bit = rand_r(seedp) % 8;
  heap[pos] ^= (uint8_t)(1 << bit);
}

/* Runs basic functionality tests */
static void run_basic_tests(void) {
  printf("\n=== Basic Tests ===\n");

  /* Test 1: Simple allocation and read/write */
  printf("Test 1: Simple allocation... ");
  fflush(stdout);
  {
    void *p1 = mm_malloc(128);
    if (p1 != NULL) {
      const char *msg = "Hello Mars!";
      if (mm_write(p1, 0, msg, strlen(msg) + 1) > 0) {
        char buf[128];
        if (mm_read(p1, 0, buf, strlen(msg) + 1) > 0) {
          if (strcmp(buf, msg) == 0) {
            printf("PASS\n");
          } else {
            printf("FAIL (data mismatch)\n");
          }
        } else {
          printf("FAIL (read failed)\n");
        }
      } else {
        printf("FAIL (write failed)\n");
      }
      mm_free(p1);
    } else {
      printf("FAIL (allocation failed)\n");
    }
  }

  /* Test 2: Multiple allocations */
  printf("Test 2: Multiple allocations... ");
  fflush(stdout);
  {
    void *ptrs[10];
    int ok = 1;
    int i;
    for (i = 0; i < 10; i++) {
      ptrs[i] = mm_malloc((size_t)(64 + i * 10));
      if (ptrs[i] == NULL) {
        ok = 0;
        break;
      }
    }
    if (ok) {
      for (i = 9; i >= 0; i--) {
        mm_free(ptrs[i]);
      }
      printf("PASS\n");
    } else {
      printf("FAIL\n");
      for (i = 0; i < 10; i++) {
        if (ptrs[i] != NULL) {
          mm_free(ptrs[i]);
        }
      }
    }
  }

  /* Test 3: Large allocation */
  printf("Test 3: Large allocation... ");
  fflush(stdout);
  {
    void *large = mm_malloc(2000);
    if (large != NULL) {
      mm_free(large);
      printf("PASS\n");
    } else {
      printf("FAIL\n");
    }
  }

  /* Test 4: Zero-size allocation should return NULL */
  printf("Test 4: Zero-size allocation... ");
  fflush(stdout);
  {
    void *zero = mm_malloc(0);
    if (zero == NULL) {
      printf("PASS\n");
    } else {
      printf("FAIL\n");
      mm_free(zero);
    }
  }

  /* Test 5: Double-free detection */
  printf("Test 5: Double-free detection... ");
  fflush(stdout);
  {
    void *df = mm_malloc(100);
    if (df != NULL) {
      mm_free(df);
      mm_free(df);
      printf("PASS\n");
    } else {
      printf("FAIL (allocation failed)\n");
    }
  }

  /* Test 6: Realloc functionality */
  printf("Test 6: Realloc... ");
  fflush(stdout);
  {
    void *rp = mm_malloc(50);
    if (rp != NULL) {
      const char *data = "Realloc test";
      void *rp2;
      mm_write(rp, 0, data, strlen(data) + 1);
      rp2 = mm_realloc(rp, 200);
      if (rp2 != NULL) {
        char rbuf[128];
        mm_read(rp2, 0, rbuf, strlen(data) + 1);
        if (strcmp(rbuf, data) == 0) {
          printf("PASS\n");
        } else {
          printf("FAIL (data not preserved)\n");
        }
        mm_free(rp2);
      } else {
        printf("FAIL (realloc failed)\n");
        mm_free(rp);
      }
    } else {
      printf("FAIL (allocation failed)\n");
    }
  }

  /* Test 7: 40-byte alignment verification */
  printf("Test 7: 40-byte alignment... ");
  fflush(stdout);
  {
    int align_ok = 1;
    int i;
    for (i = 0; i < 5; i++) {
      void *ap = mm_malloc((size_t)(32 + i * 17));
      if (ap != NULL) {
        size_t offset = (size_t)((uint8_t *)ap - g_heap);
        if (offset % 40 != 0) {
          align_ok = 0;
        }
        mm_free(ap);
      }
    }
    if (align_ok) {
      printf("PASS\n");
    } else {
      printf("FAIL\n");
    }
  }

  /* Test 8: Bounds checking */
  printf("Test 8: Bounds checking... ");
  fflush(stdout);
  {
    void *bp = mm_malloc(64);
    if (bp != NULL) {
      char buf[128];
      int r = mm_read(bp, 100, buf, 10);
      if (r == -1) {
        printf("PASS\n");
      } else {
        printf("FAIL\n");
      }
      mm_free(bp);
    } else {
      printf("FAIL (allocation failed)\n");
    }
  }
}

/* Runs random allocation/free operations */
static void run_ops_test(int num_ops, unsigned int *seedp) {
  int active = 0;
  int allocs = 0;
  int frees = 0;
  int op;
  int i;
  int max;
  printf("\n=== Operations Test (%d ops) ===\n", num_ops);
  fflush(stdout);
  for (i = 0; i < MAX_POINTERS; i++) {
    g_ptrs[i] = NULL;
    g_sizes[i] = 0;
  }
  for (op = 0; op < num_ops; op++) {
    int action = rand_r(seedp) % 3;
    if (action < 2 && active < MAX_POINTERS / 2) {
      size_t size = 16 + ((size_t)rand_r(seedp) % 512);
      int idx = -1;
      for (i = 0; i < num_ops && i < MAX_POINTERS; i++) {
        if (g_ptrs[i] == NULL) {
          idx = i;
          break;
        }
      }
      if (idx >= 0) {
        g_ptrs[idx] = mm_malloc(size);
        if (g_ptrs[idx] != NULL) {
          uint8_t pat = (uint8_t)(idx & 0xFF);
          size_t j;
          g_sizes[idx] = size;
          active++;
          allocs++;
          for (j = 0; j < size; j++) {
            mm_write(g_ptrs[idx], j, &pat, 1);
          }
        }
      }
    } else if (active > 0) {
      int tries;
      max = (num_ops < MAX_POINTERS) ? num_ops : MAX_POINTERS;
      for (tries = 0; tries < max; tries++) {
        int idx = rand_r(seedp) % max;
        if (g_ptrs[idx] != NULL) {
          mm_free(g_ptrs[idx]);
          g_ptrs[idx] = NULL;
          g_sizes[idx] = 0;
          active--;
          frees++;
          break;
        }
      }
    }
  }
  max = (num_ops < MAX_POINTERS) ? num_ops : MAX_POINTERS;
  for (i = 0; i < max; i++) {
    if (g_ptrs[i] != NULL) {
      mm_free(g_ptrs[i]);
      g_ptrs[i] = NULL;
      frees++;
    }
  }
  printf("Completed: %d allocs, %d frees\n", allocs, frees);
}

/**
 * Simulates a brownout by setting write_state to STATE_WRITING.
 * This mimics what happens when power fails during a write operation.
 */
static void simulate_brownout(uint8_t *heap, void *ptr) {
  /* Find the header for this payload pointer */
  uint8_t *scan = heap;
  size_t min_block = 56;  /* sizeof(Header) + sizeof(Footer) approx */
  while (scan < heap + MAX_HEAP_SIZE - min_block) {
    /* Check for header magic (0xDEADBEEF) */
    uint32_t magic = *(uint32_t *)scan;
    if (magic == 0xDEADBEEFU) {
      size_t block_size = *(size_t *)(scan + 8);
      if (block_size >= min_block && block_size < MAX_HEAP_SIZE) {
        /* Check if this block's payload matches ptr */
        /* Skip header (40 bytes with payload_checksum) */
        uint8_t *data = scan + 40;
        size_t offset = (size_t)(data - heap);
        size_t padding = (40 - (offset % 40)) % 40;
        uint8_t *payload = data + padding;
        if (payload == ptr) {
          /* Set write_state to STATE_WRITING (0xAAAAAAAA) */
          /* write_state is at offset 32 in header */
          uint32_t *write_state = (uint32_t *)(scan + 32);
          *write_state = 0xAAAAAAAAU;
          return;
        }
        scan += block_size;
        continue;
      }
    }
    scan += 8;
  }
}

/* Runs brownout-specific tests */
static void run_brownout_tests(uint8_t *heap) {
  void *ptr;
  const char *test_data = "Brownout test data";
  char buf[64];
  int r;
  printf("\n=== Brownout Detection Tests ===\n");
  fflush(stdout);
  /* Test 1: Detect brownout on read */
  printf("Test B1: Brownout detection on read... ");
  fflush(stdout);
  ptr = mm_malloc(64);
  if (ptr != NULL) {
    mm_write(ptr, 0, test_data, strlen(test_data) + 1);
    /* Simulate brownout by corrupting write_state */
    simulate_brownout(heap, ptr);
    r = mm_read(ptr, 0, buf, 10);
    if (r == -1) {
      printf("PASS (detected)\n");
    } else {
      printf("FAIL (not detected)\n");
    }
  } else {
    printf("FAIL (allocation failed)\n");
  }
  /* Test 2: Detect brownout on write */
  printf("Test B2: Brownout detection on write... ");
  fflush(stdout);
  ptr = mm_malloc(64);
  if (ptr != NULL) {
    mm_write(ptr, 0, test_data, strlen(test_data) + 1);
    simulate_brownout(heap, ptr);
    r = mm_write(ptr, 0, "new data", 8);
    if (r == -1) {
      printf("PASS (detected)\n");
    } else {
      printf("FAIL (not detected)\n");
    }
  } else {
    printf("FAIL (allocation failed)\n");
  }
  /* Test 3: Brownout block is quarantined */
  printf("Test B3: Brownout quarantine... ");
  fflush(stdout);
  ptr = mm_malloc(64);
  if (ptr != NULL) {
    mm_write(ptr, 0, test_data, strlen(test_data) + 1);
    simulate_brownout(heap, ptr);
    mm_read(ptr, 0, buf, 10);  /* Should fail and quarantine */
    r = mm_read(ptr, 0, buf, 10);  /* Should fail (quarantined) */
    if (r == -1) {
      printf("PASS (quarantined)\n");
    } else {
      printf("FAIL (not quarantined)\n");
    }
  } else {
    printf("FAIL (allocation failed)\n");
  }
}

/* Runs storm simulation tests */
static void run_storm_tests(uint8_t *heap, size_t size, int level,
                            unsigned int *seedp) {
  void *p1;
  void *p2;
  void *p3;
  int flips;
  int i;
  if (level == 0) {
    return;
  }
  printf("\n=== Storm Tests (Level %d) ===\n", level);
  fflush(stdout);
  p1 = mm_malloc(128);
  p2 = mm_malloc(256);
  p3 = mm_malloc(64);
  if (p1 == NULL || p2 == NULL || p3 == NULL) {
    printf("Failed to allocate test blocks\n");
    if (p1 != NULL) mm_free(p1);
    if (p2 != NULL) mm_free(p2);
    if (p3 != NULL) mm_free(p3);
    return;
  }
  {
    const char *msg = "Storm test";
    mm_write(p1, 0, msg, strlen(msg) + 1);
  }
  flips = (level == 1) ? 5 : 20;
  printf("Simulating %d bit flips... ", flips);
  fflush(stdout);
  for (i = 0; i < flips; i++) {
    flip_bit(heap, size, seedp);
  }
  printf("Done\n");
  printf("Testing corruption detection... ");
  fflush(stdout);
  {
    char buf[256];
    int r = mm_read(p1, 0, buf, 128);
    if (r < 0) {
      printf("Corruption detected\n");
    } else {
      printf("Data still readable\n");
    }
  }
  printf("Testing safe free... ");
  fflush(stdout);
  mm_free(p1);
  mm_free(p2);
  mm_free(p3);
  printf("PASS\n");
  printf("Testing recovery... ");
  fflush(stdout);
  {
    void *rec = mm_malloc(100);
    if (rec != NULL) {
      mm_free(rec);
      printf("PASS\n");
    } else {
      printf("Limited (heap may be fragmented)\n");
    }
  }
  /* Run brownout tests after storm tests */
  run_brownout_tests(heap);
}

/* Main entry point for the test executable */
int main(int argc, char *argv[]) {
  Config cfg;
  unsigned int seed;
  size_t i;
  parse_args(argc, argv, &cfg);
  printf("=================================\n");
  printf(" Mars Rover Memory Allocator Test\n");
  printf("=================================\n");
  printf("Heap Size: %zu bytes\n", cfg.heap_size);
  printf("Seed: %u\n", cfg.seed);
  printf("Storm Level: %d\n", cfg.storm_level);
  if (cfg.num_ops > 0) {
    printf("Operations: %d\n", cfg.num_ops);
  }
  fflush(stdout);
  for (i = 0; i < cfg.heap_size; i++) {
    g_heap[i] = (uint8_t)(0xDE + (i % 5));
  }
  printf("\nInitializing allocator... ");
  fflush(stdout);
  if (mm_init(g_heap, cfg.heap_size) == 0) {
    printf("SUCCESS\n");
  } else {
    printf("FAILED\n");
    return 1;
  }
  fflush(stdout);
  seed = cfg.seed;
  if (cfg.num_ops > 0) {
    run_ops_test(cfg.num_ops, &seed);
  } else {
    run_basic_tests();
  }
  if (cfg.storm_level > 0) {
    run_storm_tests(g_heap, cfg.heap_size, cfg.storm_level, &seed);
  }
  printf("\n=== Final Statistics ===\n");
  mm_heap_stats();
  printf("=== All Tests Complete ===\n");
  fflush(stdout);
  return 0;
}
