// Copyright 2023 Dave Watson
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700

#include "profiler.h"
#include "hawk.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static const useconds_t k_sample_interval_usec = 5; // 0.25ms

static volatile sig_atomic_t sample_ticks = 0;
static volatile sig_atomic_t total_samples = 0;
static volatile sig_atomic_t jit_samples = 0;
static volatile sig_atomic_t gc_samples = 0;
static bool profiler_running = false;
static struct sigaction prev_sa;
static bool prev_sa_valid = false;

static volatile sig_atomic_t jit_active = 0;
static volatile sig_atomic_t gc_active = 0;
static volatile sig_atomic_t gc_depth = 0;

void profiler_register_jit_symbol(void *start, void *end, const char *name) {
  (void)start;
  (void)end;
  (void)name;
}

static void handler(int sig, siginfo_t *si, void *uc) {
  (void)sig;
  (void)si;
  (void)uc;
  sample_ticks++;
  total_samples++;
  if (gc_active) {
    gc_samples++;
  } else if (jit_active) {
    jit_samples++;
  }
}

void profiler_set_in_jit(bool active) { jit_active = active ? 1 : 0; }

void profiler_set_in_gc(bool active) {
  if (active) {
    gc_depth++;
    gc_active = 1;
  } else {
    if (gc_depth > 0) {
      gc_depth--;
    }
    if (gc_depth == 0) {
      gc_active = 0;
    }
  }
}

uint64_t profiler_gc_enter(void) {
  gc_depth++;
  gc_active = 1;
  return (uint64_t)total_samples;
}

void profiler_gc_exit(uint64_t start_total_samples, uint64_t duration_ns) {
  if (gc_depth > 0) {
    gc_depth--;
  }
  if (gc_depth == 0) {
    gc_active = 0;
  }
  uint64_t expected = duration_ns / ((uint64_t)k_sample_interval_usec * 1000ULL);
  uint64_t actual = 0;
  sig_atomic_t cur_total = total_samples;
  if ((uint64_t)cur_total > start_total_samples) {
    actual = (uint64_t)cur_total - start_total_samples;
  }
  if (expected > actual) {
    uint64_t missing = expected - actual;
    total_samples += (sig_atomic_t)missing;
    gc_samples += (sig_atomic_t)missing;
  }
}

EXPORT void profiler_start(void) {
  if (profiler_running) {
    return;
  }
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGPROF, &sa, &prev_sa) == -1) {
    perror("sigaction");
    exit(EXIT_FAILURE);
  }
  prev_sa_valid = true;

  struct itimerval timer;
  memset(&timer, 0, sizeof(timer));
  timer.it_value.tv_sec = 0;
  timer.it_value.tv_usec = (suseconds_t)k_sample_interval_usec;
  timer.it_interval = timer.it_value;
  if (setitimer(ITIMER_PROF, &timer, nullptr) == -1) {
    perror("setitimer");
    exit(EXIT_FAILURE);
  }
  sample_ticks = 0;
  total_samples = 0;
  jit_samples = 0;
  gc_samples = 0;
  profiler_running = true;
}

EXPORT void profiler_stop(void) {
  if (!profiler_running) {
    return;
  }
  struct itimerval disable;
  memset(&disable, 0, sizeof(disable));
  setitimer(ITIMER_PROF, &disable, nullptr);
  if (prev_sa_valid) {
    sigaction(SIGPROF, &prev_sa, nullptr);
    prev_sa_valid = false;
  }
  profiler_running = false;
  printf("Timer fired %d times\n", sample_ticks);
  uint64_t tot = total_samples;
  uint64_t on_trace = jit_samples;
  uint64_t on_gc = gc_samples;
  if (tot == 0) {
    printf("No samples collected\n");
    return;
  }

  double total = (double)tot;
  printf("On-trace: %.02f%%\n", (double)on_trace / total * 100.0);
  printf("In-gc: %.02f%%\n", (double)on_gc / total * 100.0);
  double other = (double)(tot - (on_gc + on_trace));
  double vm_pct = other / total * 100.0;
  printf("VM: %.02f%%\n", vm_pct);
}
