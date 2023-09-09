#include "bytecode.h"    // for bcfunc, INS_OP, ins_names
#include "vm.h"          // for find_func_for_frame
#include "defs.h"

#include <assert.h>       // for assert
#include <signal.h>       // for sigaction, sigevent, SIGRTMIN
#include <stdint.h>       // for uint32_t
#include <stdio.h>        // for printf
#include <stdlib.h>       // for exit, free, malloc
#include <string.h>       // for memcpy
#include <time.h>         // for timer_settime, timespec
#include <sys/mman.h>    // for mmap, MAP_ANONYMOUS, MAP_P...
#include <stdbool.h>

#define auto __auto_type
#define nullptr NULL

static timer_t timerid;
static struct itimerspec its;
static long cnt = 0;

static unsigned long heap_ptr = 0;
static unsigned long heap_end = 0;

static size_t alloc_sz = 4096 * 16;

void *signal_safe_malloc(size_t sz) {
  if ((heap_ptr + sz) < heap_end) {
    auto res = heap_ptr;
    heap_ptr += sz;
    return (void *)res;
  }
  assert(sz < alloc_sz);
  heap_ptr = (unsigned long)mmap(nullptr, alloc_sz, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  assert(heap_ptr);
  heap_end = heap_ptr + alloc_sz;
  auto res = heap_ptr;
  heap_ptr += sz;
  return (void *)res;
}

typedef struct sample_s {
  long stack_sz;
  long stack[10];
  struct sample_s *next;
  bool in_jit;
  bool in_gc;
} sample;

static sample *samples = nullptr;

static unsigned long profile_stack_sz = 0;
static long *profile_stack = nullptr;
static unsigned long profile_stack_max = 0;
static uint32_t *pc;

void profile_set_pc(uint32_t *p) { pc = p; }

void profile_add_frame(void *ptr) {
  if (profile_stack_sz >= profile_stack_max) {
    if (profile_stack_max == 0) {
      profile_stack_max = 1000;
    } else {
      profile_stack_max *= 2;
    }
    auto *n = (long *)malloc(sizeof(long) * profile_stack_max);
    memcpy(n, profile_stack, profile_stack_sz * sizeof(long));
    auto *old = profile_stack;
    profile_stack = n; // release
    free(old);
    printf("Expanded profile stack to %li\n", profile_stack_max);
  }
  profile_stack[profile_stack_sz] = (long)ptr;
  profile_stack_sz++; // release
}

void profile_pop_frame() {
  // TODO make callcc resume work
  if (profile_stack_sz > 0) {
    profile_stack_sz--;
  }
}

void profile_pop_all_frames() { profile_stack_sz = 0; }

extern bool in_jit;
extern bool in_gc;
static void handler(int sig, siginfo_t *si, void *uc) {
  cnt++;
  auto *s = (sample *)signal_safe_malloc(sizeof(sample));
  s->next = samples;
  s->stack_sz = 9 < profile_stack_sz ? 9 : profile_stack_sz;
  memcpy(&s->stack[0], &profile_stack[profile_stack_sz - s->stack_sz],
         s->stack_sz * sizeof(long));
  s->stack[s->stack_sz] = (long)pc;
  s->stack_sz++;
  s->in_jit = in_jit;
  s->in_gc = in_gc;
  samples = s;
  if (timer_settime(timerid, 0, &its, nullptr) == -1) {
    exit(-2);
  }
}

EXPORT void profiler_start() {
  struct sigevent sev;

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handler;
  if (sigaction(SIGRTMIN, &sa, nullptr) == -1) {
    printf("Could not install signal handler profiler\n");
    exit(-1);
  }

  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGRTMIN;
  sev.sigev_value.sival_ptr = &timerid;
  auto res = timer_create(CLOCK_MONOTONIC, &sev, &timerid);
  if (res == -1) {
    printf("Could not create profile timer\n");
    exit(-1);
  }
  //printf("Timer id is %li\n", (long)timerid);

  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = 250000;
  its.it_interval.tv_sec = 0;
  its.it_interval.tv_nsec = 0;
  if (timer_settime(timerid, 0, &its, nullptr) == -1) {
    printf("Could not timer_settime \n");
    exit(-1);
  }
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
/*     auto *func = find_func_for_frame((uint32_t *)item.first); */
/*     if (func != nullptr) { */
/*       printf("%*c %.2f%% %s %s %li\n", indent, ' ', */
/*              (double)item.second->cnt / cnt * 100.0, func->name.c_str(), */
/*              ins_names[INS_OP(*(uint32_t *)item.first)], */
/*              (uint32_t *)item.first - (func->code).data()); */
/*     } else { */
/*       printf("%*cCan't find func for frame %li\n", indent, ' ', item.first); */
/*     } */
/*     profiler_display_tree_node(item.second, indent + 5); */
/*   } */
/* } */

EXPORT void profiler_stop() {
/*   tree tree_root; */
  timer_delete(timerid);
  uint64_t tot = 0;
  uint64_t on_trace = 0;
  uint64_t on_gc = 0;

  printf("Timer called %li times\n", cnt);
  auto *s = samples;
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
    s = s->next;
  }

  printf("On-trace: %.02f%%\n", (double)on_trace / (double)tot * 100.0);
  printf("In-gc: %.02f%%\n", (double)on_gc / (double)tot * 100.0);
  printf("VM: %.02f%%\n", 100.0-((double)(on_gc + on_trace) / (double)tot * 100.0));

/*   profiler_display_tree_node(&tree_root, 0); */
}

