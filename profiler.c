// Copyright 2023 Dave Watson

#include "profiler.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

#include "hawk.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static const useconds_t k_sample_interval_usec = 250; // 0.25ms
static volatile sig_atomic_t sample_ticks = 0;
static bool profiler_running = false;
static struct sigaction prev_sa;
static bool prev_sa_valid = false;

static uint64_t heap_ptr = 0;
static uint64_t heap_end = 0;

static size_t alloc_sz = 4096 * 16UL;

void *signal_safe_malloc(size_t sz) {
  if ((heap_ptr + sz) <= heap_end) {
    auto res = heap_ptr;
    heap_ptr += sz;
    return (void *)res;
  }
  size_t chunk = alloc_sz;
  if (sz > chunk) {
    size_t page = (size_t)getpagesize();
    chunk = ((sz + page - 1) / page) * page;
  }
  void *mem =
      mmap(nullptr, chunk, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
           -1, 0);
  if (mem == MAP_FAILED) {
    _exit(1);
  }
  heap_ptr = (uint64_t)mem;
  heap_end = heap_ptr + chunk;
  auto res = heap_ptr;
  heap_ptr += sz;
  return (void *)res;
}

typedef struct sample_s {
  int64_t stack_sz;
  uint32_t *stack[10];
  struct sample_s *next;
  bool in_jit;
  bool in_gc;
} sample;

static sample *samples = nullptr;

static size_t profile_stack_sz = 0;
static uint32_t **profile_stack = nullptr;
static size_t profile_stack_max = 0;
static uint32_t *pc;
static bool jit_active = false;
static bool gc_active = false;

void profile_set_pc(uint32_t *p) { pc = p; }

void profile_add_frame(uint32_t *ptr) {
  if (profile_stack_sz >= profile_stack_max) {
    if (profile_stack_max == 0) {
      profile_stack_max = 1000;
    } else {
      profile_stack_max *= 2;
    }
    uint32_t **n =
        realloc(profile_stack, sizeof(uint32_t *) * profile_stack_max);
    if (!n) {
      perror("realloc profile stack");
      exit(EXIT_FAILURE);
    }
    profile_stack = n;
    printf("Expanded profile stack to %zu\n", profile_stack_max);
  }
  profile_stack[profile_stack_sz] = ptr;
  profile_stack_sz++; // release
}

void profile_pop_frame() {
  // TODO(djwatson) make callcc resume work
  if (profile_stack_sz > 0) {
    profile_stack_sz--;
  }
}

void profile_pop_all_frames() { profile_stack_sz = 0; }

static void handler(int sig, siginfo_t *si, void *uc) {
  (void)sig;
  (void)si;
  (void)uc;
  sample_ticks++;
  sample *s = signal_safe_malloc(sizeof(sample));
  s->next = samples;
  size_t max_backtrace = 9;
  size_t frames_to_copy =
      profile_stack_sz < max_backtrace ? profile_stack_sz : max_backtrace;
  size_t start = profile_stack_sz - frames_to_copy;
  for (size_t i = 0; i < frames_to_copy; i++) {
    s->stack[i] = profile_stack[start + i];
  }
  s->stack_sz = frames_to_copy;
  if (s->stack_sz < (sizeof(s->stack) / sizeof(s->stack[0]))) {
    s->stack[s->stack_sz] = pc;
    s->stack_sz++;
  }
  s->in_jit = jit_active;
  s->in_gc = gc_active;
  samples = s;
}

void profiler_set_in_jit(bool active) { jit_active = active; }

void profiler_set_in_gc(bool active) { gc_active = active; }

EXPORT void profiler_start() {
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
  timer.it_value.tv_usec = k_sample_interval_usec;
  timer.it_interval = timer.it_value;
  if (setitimer(ITIMER_PROF, &timer, nullptr) == -1) {
    perror("setitimer");
    exit(EXIT_FAILURE);
  }
  samples = nullptr;
  sample_ticks = 0;
  profiler_running = true;
}

/* struct tree { */
/*   long cnt; */
/*   std::unordered_map<long, tree> next; */
/* }; */

/* static void profiler_display_tree_node(const tree *node, int indent) { */
/*   std::vector<std::pair<long, const tree *>> nodes; */
/*   for (const auto &leaf : node->next) { */
/*     if (leaf.second.cnt > cnt / 100) { */
/*       nodes.emplace_back(leaf.first, &leaf.second); */
/*     } */
/*   } */

/*   if (nodes.empty()) { */
/*     return; */
/*   } */

/*   auto sorter = [](std::pair<long, const tree *> const &s1, */
/*                    std::pair<long, const tree *> const &s2) { */
/*     return s1.second->cnt > s2.second->cnt; */
/*   }; */
/*   std::sort(nodes.begin(), nodes.end(), sorter); */
/*   for (auto &item : nodes) { */
/*     auto func = find_func_for_frame((uint32_t *)item.first); */
/*     if (func != nullptr) { */
/*       printf("%*c %.2f%% %s %s %li\n", indent, ' ', */
/*              (double)item.second->cnt / cnt * 100.0, func->name.c_str(), */
/*              ins_names[INS_OP(*(uint32_t *)item.first)], */
/*              (uint32_t *)item.first - (func->code).data()); */
/*     } else { */
/*       printf("%*cCan't find func for frame %li\n", indent, ' ', item.first);
 */
/*     } */
/*     profiler_display_tree_node(item.second, indent + 5); */
/*   } */
/* } */

EXPORT void profiler_stop() {
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
  uint64_t tot = 0;
  uint64_t on_trace = 0;
  uint64_t on_gc = 0;

  printf("Timer fired %d times\n", sample_ticks);
  auto s = samples;
  while (s != nullptr) {
    /*     tree *cur_tree = &tree_root; */
    /*     for (int i = s->stack_sz - 1; i >= 0; i--) { */
    /*       auto frame = s->stack[i]; */
    /*       cur_tree = &cur_tree->next[frame]; */
    /*       cur_tree->cnt++; */
    /*     } */
    tot++;
    if (s->in_jit) {
      on_trace++;
    }
    if (s->in_gc) {
      on_gc++;
    }
    auto next = s->next;
    s = next;
  }
  if (tot == 0) {
    printf("No samples collected\n");
    return;
  }

  double total = (double)tot;
  printf("On-trace: %.02f%%\n", (double)on_trace / total * 100.0);
  printf("In-gc: %.02f%%\n", (double)on_gc / total * 100.0);
  double vm_pct = 100.0 - ((double)(on_gc + on_trace) / total * 100.0);
  printf("VM: %.02f%%\n", vm_pct);

  /*   profiler_display_tree_node(&tree_root, 0); */
}
