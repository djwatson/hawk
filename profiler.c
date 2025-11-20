// Copyright 2023 Dave Watson

#define _XOPEN_SOURCE 700

#include "profiler.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>

#include "hawk.h"
#include "emit.h"
#include "vm.h"

static const useconds_t k_sample_interval_usec = 250; // 0.25ms
static const size_t k_max_pc_samples = 1 << 15;
static volatile sig_atomic_t sample_ticks = 0;
static volatile sig_atomic_t total_samples = 0;
static volatile sig_atomic_t jit_samples = 0;
static volatile sig_atomic_t gc_samples = 0;
static bool profiler_running = false;
static struct sigaction prev_sa;
static bool prev_sa_valid = false;

static volatile sig_atomic_t jit_active = 0;
static volatile sig_atomic_t gc_active = 0;
static void *pc_samples[k_max_pc_samples];
static volatile sig_atomic_t pc_sample_count = 0;

static int cmp_void_ptr(const void *a, const void *b) {
  uintptr_t pa = (uintptr_t)*(void *const *)a;
  uintptr_t pb = (uintptr_t)*(void *const *)b;
  if (pa < pb) {
    return -1;
  }
  if (pa > pb) {
    return 1;
  }
  return 0;
}

typedef struct {
  void *pc;
  size_t hits;
} pc_count;

static int cmp_pc_count_desc(const void *a, const void *b) {
  size_t ha = ((const pc_count *)a)->hits;
  size_t hb = ((const pc_count *)b)->hits;
  if (ha < hb) {
    return 1;
  }
  if (ha > hb) {
    return -1;
  }
  return 0;
}

// Extract PC from ucontext in a signal-safe way.
static void *ucontext_pc(void *uc) {
  if (!uc) {
    return nullptr;
  }
#if defined(__aarch64__)
  return (void *)((ucontext_t *)uc)->uc_mcontext->__ss.__pc;
#elif defined(__x86_64__)
  return (void *)((ucontext_t *)uc)->uc_mcontext->__ss.__rip;
#else
  (void)uc;
  return nullptr;
#endif
}

// Best-effort ring buffer store; only the handler writes, so no locks needed.
static void record_pc_sample(void *pc) {
  sig_atomic_t idx = pc_sample_count;
  if (idx >= (sig_atomic_t)k_max_pc_samples) {
    return;
  }
  pc_samples[idx] = pc;
  pc_sample_count = idx + 1;
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
    record_pc_sample(ucontext_pc(uc));
  }
}

void profiler_set_in_jit(bool active) { jit_active = active ? 1 : 0; }

void profiler_set_in_gc(bool active) { gc_active = active ? 1 : 0; }

EXPORT void profiler_start(vm_state *state) {
  if (profiler_running) {
    return;
  }
  // Make current hospital for later pc comments.
  if (state) {
    // Clear any old samples left from prior runs.
    pc_sample_count = 0;
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
  sample_ticks = 0;
  total_samples = 0;
  jit_samples = 0;
  gc_samples = 0;
  pc_sample_count = 0;
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

EXPORT void profiler_stop(vm_state *state) {
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

  sig_atomic_t pc_cnt = pc_sample_count;
  if (pc_cnt > 0) {
    size_t count = (size_t)pc_cnt;
    void **copy = malloc(count * sizeof(void *));
    if (!copy) {
      printf("Failed to alloc for pc samples\n");
      return;
    }
    memcpy(copy, pc_samples, count * sizeof(void *));
    qsort(copy, count, sizeof(void *), cmp_void_ptr);
    pc_count *runs = malloc(count * sizeof(pc_count));
    if (!runs) {
      free(copy);
      printf("Failed to alloc for pc histogram\n");
      return;
    }

    size_t run_len = 0;
    for (size_t i = 0; i < count;) {
      size_t j = i + 1;
      while (j < count && copy[j] == copy[i]) {
        j++;
      }
      runs[run_len].pc = copy[i];
      runs[run_len].hits = j - i;
      run_len++;
      i = j;
    }
    free(copy);

    qsort(runs, run_len, sizeof(pc_count), cmp_pc_count_desc);

    size_t to_print = run_len < 10 ? run_len : 10;
    printf("Top JIT PCs (samples=%zu):\n", (size_t)pc_cnt);
    for (size_t i = 0; i < to_print; i++) {
      printf("  pc=%p hits=%zu\n", runs[i].pc, runs[i].hits);
    }
    if (state) {
      for (size_t i = 0; i < to_print; i++) {
        emit_add_global_comment(&state->emit, (int64_t)(uintptr_t)runs[i].pc,
                                "HOT pc=%p hits=%zu", runs[i].pc, runs[i].hits);
      }
    }
    free(runs);
  }

  /*   profiler_display_tree_node(&tree_root, 0); */
}
