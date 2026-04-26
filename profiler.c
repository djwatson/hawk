// Copyright 2023 Dave Watson
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include "profiler.h"
#include "hawk.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// This profiler just tracks wall time spent in three regions:
//  - On-trace (JIT)
//  - GC (gc_collect)
//  - VM/off-trace

typedef enum {
  BUCKET_VM = 0,
  BUCKET_JIT = 1,
  BUCKET_GC = 2,
  BUCKET_COUNT = 3,
} profiler_bucket;

static clockid_t profiler_clock = CLOCK_MONOTONIC;
static uint64_t bucket_time_ns[BUCKET_COUNT];
static profiler_bucket current_bucket = BUCKET_VM;
static profiler_bucket pre_gc_bucket = BUCKET_VM;
static uint64_t last_timestamp_ns = 0;
static bool profiler_running = false;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(profiler_clock, &ts);
  return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void switch_bucket(profiler_bucket next) {
  uint64_t now = now_ns();
  bucket_time_ns[current_bucket] += now - last_timestamp_ns;
  last_timestamp_ns = now;
  current_bucket = next;
}

void profiler_register_jit_symbol(void *start, void *end, const char *name) {
  (void)start;
  (void)end;
  (void)name;
}

void profiler_start(void) {
  if (profiler_running) {
    return;
  }
  profiler_reset();
  profiler_running = true;
}

void profiler_reset(void) {
  profiler_clock = CLOCK_MONOTONIC;
  memset(bucket_time_ns, 0, sizeof(bucket_time_ns));
  current_bucket = BUCKET_VM;
  pre_gc_bucket = BUCKET_VM;
  last_timestamp_ns = now_ns();
}

void profiler_stop(void) {
  if (!profiler_running) {
    return;
  }
  // Close the current bucket.
  switch_bucket(current_bucket);
  profiler_running = false;

  uint64_t total_ns = bucket_time_ns[0] + bucket_time_ns[1] + bucket_time_ns[2];
  if (total_ns == 0) {
    printf("No profiler time recorded\n");
    return;
  }
  double total = (double)total_ns;
  double on_trace_pct = (double)bucket_time_ns[BUCKET_JIT] / total * 100.0;
  double gc_pct = (double)bucket_time_ns[BUCKET_GC] / total * 100.0;
  double vm_pct = (double)bucket_time_ns[BUCKET_VM] / total * 100.0;

  printf("\nOn-trace: %.02f%% (%.3f ms)\n", on_trace_pct,
         (double)bucket_time_ns[BUCKET_JIT] / 1e6);
  printf("In-gc: %.02f%% (%.3f ms)\n", gc_pct,
         (double)bucket_time_ns[BUCKET_GC] / 1e6);
  printf("VM: %.02f%% (%.3f ms)\n", vm_pct,
         (double)bucket_time_ns[BUCKET_VM] / 1e6);
}

void profiler_set_in_jit(bool active) {
  assert(current_bucket != BUCKET_GC);
  if (!profiler_running) {
    return;
  }
  if (active) {
    switch_bucket(BUCKET_JIT);
  } else {
    switch_bucket(BUCKET_VM);
  }
}

void profiler_set_in_gc(bool active) {
  if (!profiler_running) {
    return;
  }
  if (active) {
    pre_gc_bucket = current_bucket;
    switch_bucket(BUCKET_GC);
  } else {
    assert(current_bucket == BUCKET_GC);
    switch_bucket(pre_gc_bucket);
  }
}
