/* Copyright 2025 COMP2221 Systems Programming */
/*
 * Mars Rover Memory Allocator Test Driver
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "allocator.h"

/* Configuration defaults */
#define DEFAULT_SIZE 8192
#define DEFAULT_SEED 42
#define DEFAULT_STORM 0
#define MAX_SIZE 1048576
#define MAX_PTRS 1000

/* Static heap buffer - no malloc used for heap */
static uint8_t g_heap[MAX_SIZE];
static void *g_ptrs[MAX_PTRS];
static size_t g_sizes[MAX_PTRS];

typedef struct {
  size_t heap_size;
  unsigned int seed;
  int storm_level;
  int num_ops;
} Config;

static void print_usage(const char *name) {
  printf("Usage: %s [OPTIONS]\n", name);
  printf("Options:\n");
  printf("  --size <bytes>   Heap size (default: %d)\n", DEFAULT_SIZE);
  printf("  --seed <num>     Random seed (default: %d)\n", DEFAULT_SEED);
  printf("  --storm <level>  Storm: 0=none, 1=light, 2=heavy\n");
  printf("  --ops <num>      Number of operations\n");
  printf("  --help           Show this message\n");
}

static void parse_args(int argc, char *argv[], Config *cfg) {
  cfg->heap_size = DEFAULT_SIZE;
  cfg->seed = DEFAULT_SEED;
  cfg->storm_level = DEFAULT_STORM;
  cfg->num_ops = 0;

  static struct option opts[] = {
    {"size", required_argument, 0, 's'},
    {"seed", required_argument, 0, 'r'},
    {"storm", required_argument, 0, 't'},
    {"ops", required_argument, 0, 'o'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  int c;
  int idx = 0;
  while ((c = getopt_long(argc, argv, "s:r:t:o:h", opts, &idx)) != -1) {
    switch (c) {
      case 's':
        cfg->heap_size = (size_t)atoi(optarg);
        if (cfg->heap_size < 1024 || cfg->heap_size > MAX_SIZE) {
          printf("Error: size must be 1024-%d\n", MAX_SIZE);
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
        if (cfg->num_ops < 0 || cfg->num_ops > MAX_PTRS) {
          printf("Error: ops must be 0-%d\n", MAX_PTRS);
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

static void flip_bit(uint8_t *heap, size_t size, unsigned int *seedp) {
  size_t pos = (size_t)rand_r(seedp) % size;
  int bit = rand_r(seedp) % 8;
  heap[pos] ^= (uint8_t)(1 << bit);
}

static void run_basic_tests(void) {
  printf("\n=== Basic Tests ===\n");

  /* Test 1: Simple alloc/free */
  printf("Test 1: Simple allocation... ");
  fflush(stdout);
  void *p1 = mm_malloc(128);
  if (p1) {
    const char *msg = "Hello Mars!";
    if (mm_write(p1, 0, msg, strlen(msg) + 1) > 0) {
      char buf[128];
      if (mm_read(p1, 0, buf, strlen(msg) + 1) > 0) {
        if (strcmp(buf, msg) == 0) {
          printf("PASS\n");
        } else {
          printf("FAIL (mismatch)\n");
        }
      } else {
        printf("FAIL (read)\n");
      }
    } else {
      printf("FAIL (write)\n");
    }
    mm_free(p1);
  } else {
    printf("FAIL (alloc)\n");
  }

  /* Test 2: Multiple allocations */
  printf("Test 2: Multiple allocations... ");
  fflush(stdout);
  void *ptrs[10];
  int ok = 1;
  for (int i = 0; i < 10; i++) {
    ptrs[i] = mm_malloc((size_t)(64 + i * 10));
    if (!ptrs[i]) {
      ok = 0;
      break;
    }
  }
  if (ok) {
    for (int i = 9; i >= 0; i--) {
      mm_free(ptrs[i]);
    }
    printf("PASS\n");
  } else {
    printf("FAIL\n");
    for (int i = 0; i < 10; i++) {
      if (ptrs[i]) mm_free(ptrs[i]);
    }
  }

  /* Test 3: Large allocation */
  printf("Test 3: Large allocation... ");
  fflush(stdout);
  void *large = mm_malloc(2000);
  if (large) {
    mm_free(large);
    printf("PASS\n");
  } else {
    printf("FAIL\n");
  }

  /* Test 4: Zero-size */
  printf("Test 4: Zero-size allocation... ");
  fflush(stdout);
  void *zero = mm_malloc(0);
  if (zero == NULL) {
    printf("PASS\n");
  } else {
    printf("FAIL\n");
    mm_free(zero);
  }

  /* Test 5: Double-free */
  printf("Test 5: Double-free detection... ");
  fflush(stdout);
  void *df = mm_malloc(100);
  if (df) {
    mm_free(df);
    mm_free(df);  /* Should not crash */
    printf("PASS\n");
  } else {
    printf("FAIL (alloc)\n");
  }

  /* Test 6: Realloc */
  printf("Test 6: Realloc... ");
  fflush(stdout);
  void *rp = mm_malloc(50);
  if (rp) {
    const char *data = "Realloc test";
    mm_write(rp, 0, data, strlen(data) + 1);
    void *rp2 = mm_realloc(rp, 200);
    if (rp2) {
      char rbuf[128];
      mm_read(rp2, 0, rbuf, strlen(data) + 1);
      if (strcmp(rbuf, data) == 0) {
        printf("PASS\n");
      } else {
        printf("FAIL (data)\n");
      }
      mm_free(rp2);
    } else {
      printf("FAIL (realloc)\n");
      mm_free(rp);
    }
  } else {
    printf("FAIL (alloc)\n");
  }

  /* Test 7: Alignment check */
  printf("Test 7: 40-byte alignment... ");
  fflush(stdout);
  int align_ok = 1;
  for (int i = 0; i < 5; i++) {
    void *ap = mm_malloc((size_t)(32 + i * 17));
    if (ap) {
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

  /* Test 8: Bounds checking */
  printf("Test 8: Bounds checking... ");
  fflush(stdout);
  void *bp = mm_malloc(64);
  if (bp) {
    char buf[128];
    int r = mm_read(bp, 100, buf, 10);  /* Out of bounds */
    if (r == -1) {
      printf("PASS\n");
    } else {
      printf("FAIL\n");
    }
    mm_free(bp);
  } else {
    printf("FAIL (alloc)\n");
  }
}

static void run_ops_test(int num_ops, unsigned int *seedp) {
  printf("\n=== Operations Test (%d ops) ===\n", num_ops);
  fflush(stdout);

  for (int i = 0; i < MAX_PTRS; i++) {
    g_ptrs[i] = NULL;
    g_sizes[i] = 0;
  }

  int active = 0;
  int allocs = 0;
  int frees = 0;

  for (int op = 0; op < num_ops; op++) {
    int action = rand_r(seedp) % 3;

    if (action < 2 && active < MAX_PTRS / 2) {
      /* Allocate */
      size_t size = 16 + ((size_t)rand_r(seedp) % 512);
      int idx = -1;

      for (int i = 0; i < num_ops && i < MAX_PTRS; i++) {
        if (g_ptrs[i] == NULL) {
          idx = i;
          break;
        }
      }

      if (idx >= 0) {
        g_ptrs[idx] = mm_malloc(size);
        if (g_ptrs[idx]) {
          g_sizes[idx] = size;
          active++;
          allocs++;

          /* Write pattern */
          uint8_t pat = (uint8_t)(idx & 0xFF);
          for (size_t j = 0; j < size; j++) {
            mm_write(g_ptrs[idx], j, &pat, 1);
          }
        }
      }
    } else if (active > 0) {
      /* Free */
      int max = (num_ops < MAX_PTRS) ? num_ops : MAX_PTRS;
      for (int tries = 0; tries < max; tries++) {
        int idx = rand_r(seedp) % max;
        if (g_ptrs[idx]) {
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

  /* Cleanup remaining */
  int max = (num_ops < MAX_PTRS) ? num_ops : MAX_PTRS;
  for (int i = 0; i < max; i++) {
    if (g_ptrs[i]) {
      mm_free(g_ptrs[i]);
      g_ptrs[i] = NULL;
      frees++;
    }
  }

  printf("Completed: %d allocs, %d frees\n", allocs, frees);
}

static void run_storm_tests(uint8_t *heap, size_t size, int level,
                            unsigned int *seedp) {
  if (level == 0) return;

  printf("\n=== Storm Tests (Level %d) ===\n", level);
  fflush(stdout);

  void *p1 = mm_malloc(128);
  void *p2 = mm_malloc(256);
  void *p3 = mm_malloc(64);

  if (!p1 || !p2 || !p3) {
    printf("Failed to allocate test blocks\n");
    if (p1) mm_free(p1);
    if (p2) mm_free(p2);
    if (p3) mm_free(p3);
    return;
  }

  const char *msg = "Storm test";
  mm_write(p1, 0, msg, strlen(msg) + 1);

  int flips = (level == 1) ? 5 : 20;
  printf("Simulating %d bit flips... ", flips);
  fflush(stdout);

  for (int i = 0; i < flips; i++) {
    flip_bit(heap, size, seedp);
  }
  printf("Done\n");

  printf("Testing corruption detection... ");
  fflush(stdout);
  char buf[256];
  int r = mm_read(p1, 0, buf, 128);
  if (r < 0) {
    printf("Corruption detected\n");
  } else {
    printf("Data still readable\n");
  }

  printf("Testing safe free... ");
  fflush(stdout);
  mm_free(p1);
  mm_free(p2);
  mm_free(p3);
  printf("PASS\n");

  printf("Testing recovery... ");
  fflush(stdout);
  void *rec = mm_malloc(100);
  if (rec) {
    mm_free(rec);
    printf("PASS\n");
  } else {
    printf("Limited\n");
  }
}

int main(int argc, char *argv[]) {
  Config cfg;
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

  /* Initialize heap with pattern */
  for (size_t i = 0; i < cfg.heap_size; i++) {
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

  unsigned int seed = cfg.seed;

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
