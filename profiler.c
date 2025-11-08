// Copyright 2023 Dave Watson

#include "profiler.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "hawk.h"

static const useconds_t k_sample_interval_usec = 250; // 0.25ms
static volatile sig_atomic_t sample_ticks = 0;
static volatile sig_atomic_t total_samples = 0;
static volatile sig_atomic_t jit_samples = 0;
static volatile sig_atomic_t gc_samples = 0;
static bool profiler_running = false;
static struct sigaction prev_sa;
static bool prev_sa_valid = false;

static volatile sig_atomic_t jit_active = 0;
static volatile sig_atomic_t gc_active = 0;

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

void profiler_set_in_gc(bool active) { gc_active = active ? 1 : 0; }

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
  sample_ticks = 0;
  total_samples = 0;
  jit_samples = 0;
  gc_samples = 0;
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

  /*   profiler_display_tree_node(&tree_root, 0); */
}
