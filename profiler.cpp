#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>

#include <unordered_map>

// for find_func_for_frame
#include "vm.h"

static timer_t timerid;
static struct itimerspec its;
static long cnt = 0;

static unsigned long heap_ptr = 0;
static unsigned long heap_end = 0;

static size_t alloc_sz = 4096*16;

void* signal_safe_malloc(size_t sz) {
  if ((heap_ptr + sz) < heap_end) {
    auto res = heap_ptr;
    heap_ptr += sz;
    return (void*)res;
  }
  assert(sz < alloc_sz);
  heap_ptr = (unsigned long)mmap(nullptr, alloc_sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  assert(heap_ptr);
  heap_end = heap_ptr + alloc_sz;
  auto res = heap_ptr;
  heap_ptr += sz;
  return (void*)res;
}

struct sample {
  long stack_sz;
  long stack[10];
  sample* next;
};

static struct sample* samples = nullptr;

static unsigned long profile_stack_sz = 0;
static long *profile_stack = nullptr;
static unsigned long profile_stack_max = 0;

void profile_add_frame(void* ptr) {
  if (profile_stack_sz >= profile_stack_max) {
    if (profile_stack_max == 0) {
      profile_stack_max = 1000;
    } else {
      profile_stack_max *= 2;
    }
    auto n = (long*)malloc(sizeof(long) * profile_stack_max);
    memcpy(n, profile_stack, profile_stack_sz * sizeof(long));
    auto old = profile_stack;
    profile_stack = n;    // release
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

void profile_pop_all_frames() {
  profile_stack_sz = 0;
}

static void
handler(int sig, siginfo_t *si, void *uc)
{
  cnt++;
  auto s = (sample*)signal_safe_malloc(sizeof(sample));
  s->next = samples;
  s->stack_sz = 10 < profile_stack_sz ? 10 : profile_stack_sz;
  memcpy(&s->stack[0], &profile_stack[profile_stack_sz - s->stack_sz], s->stack_sz* sizeof(long));
  samples = s;
  if (timer_settime(timerid, 0, &its, nullptr) == -1) {
    exit(-2);
  }
}

void profiler_start() {
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
  printf("Timer id is %li\n", (long)timerid);

  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = 250000;
  its.it_interval.tv_sec = 0;
  its.it_interval.tv_nsec = 0;
  if (timer_settime(timerid, 0, &its, nullptr) == -1) {
    printf("Could not timer_settime \n");
    exit(-1);
  }
}

struct tree {
  long cnt{0};
  std::unordered_map<long, tree> next;
};

#include <algorithm>

static void profiler_display_tree_node(const tree* node, int indent) {
  std::vector<std::pair<long,const tree*>> nodes;
  for(const auto&leaf : node->next) {
    if (leaf.second.cnt > cnt/100) {
      nodes.push_back(std::make_pair(leaf.first, &leaf.second));
    }
  }

  if (nodes.size() == 0) {
    return;
  }
  
  auto sorter = [] (std::pair<long,const tree*> const& s1, std::pair<long,const tree*> const& s2) {
    return s1.second->cnt > s2.second->cnt;
  };
  std::sort(nodes.begin(), nodes.end(), sorter);
  for(auto& item : nodes) {
      auto func = find_func_for_frame((uint32_t*)item.first);
      if (func) {
	printf("%*c %.2f%% %s\n", indent, ' ', (double)item.second->cnt / cnt * 100.0, func->name.c_str());
      } else {
	printf("Can't find func for frame %li\n", item.first);
      }
      profiler_display_tree_node(item.second, indent+2);
  }
}

void profiler_stop() {
  tree tree_root;
  timer_delete(timerid);

  printf("Timer called %li times\n", cnt);
  auto s = samples;
  while(s) {
    tree* cur_tree = &tree_root;
    for(int i = s->stack_sz-1; i >= 0; i--) {
      auto frame = s->stack[i];
      cur_tree = &cur_tree->next[frame];
      cur_tree->cnt++;
    }
    s = s->next;
  }

  profiler_display_tree_node(&tree_root, 0);
}

