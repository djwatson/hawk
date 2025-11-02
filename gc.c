#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

// Comment out to turn off generational GC.
#define GENGC 1

#include <sys/mman.h>

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <time.h>

#include "alloc_table.h"
#include "gc.h"
#include "util/bitset.h"
#include "util/kvec.h"
#include "util/list.h"
#include "util/util.h"

static constexpr uint64_t size_classes = 4096 / 8;

// May be already defined.
#ifndef PAGE_SIZE
static constexpr uint64_t PAGE_SIZE = 1UL << 12;
#endif
static constexpr uint64_t default_slab_size = PAGE_SIZE * 4;
static uint64_t next_collect = 100000000;
static uint64_t collect_cnt = 0;
static alloc_table atable;

static uint64_t *stacktop;

uint64_t *gc_get_stack_top() { return stacktop; }

static constexpr uint64_t mark_word_cnt = (default_slab_size / 8) / 64;
static constexpr uint64_t mark_byte_cnt = (default_slab_size / 8) / 8;

typedef struct slab_info {
  uint32_t class;
  uint32_t marked;
  uint64_t markbits[mark_word_cnt];
  uint8_t *end;
  uint8_t *start;
  list_head link;
} slab_info;

static int64_t slab_sz(slab_info *slab) { return (int64_t)slab->class * 8; }

typedef struct freelist_s {
  uint64_t start_ptr;
  uint64_t end_ptr;
  slab_info *slab;
} freelist_s;

static freelist_s freelist[size_classes];
static kvec_t(slab_info *) partials[size_classes];
static LIST_HEAD(live_slabs);
static kvec_t(uint64_t *) roots;

static constexpr uint16_t page_classes = 16;
static kvec_t(slab_info *) pages_free[page_classes];

static uint64_t page_class_to_sz(uint64_t page_class) {
  return (1UL << page_class) * PAGE_SIZE;
}
static uint64_t sz_to_page_class(uint64_t sz) {
  assert(sz >= PAGE_SIZE); // Must be at least one page
  assert(sz % PAGE_SIZE == 0);

  // Convert size to number of pages
  uint64_t pages = sz / PAGE_SIZE;

  uint32_t class = 64 - __builtin_clzll(pages);

  // If already a power of two, go down one class.
  if ((pages & (pages - 1)) == 0) {
    class --;
  }

  return class;
}

bool get_partial_range(uint64_t sz_class, freelist_s *fl) {
  auto slab = fl->slab;

  int64_t end_index = -1;
  if (!slab || fl->end_ptr >= (uint64_t)slab->end) {
    if (kv_size(partials[sz_class]) > 0) {
      slab = kv_pop(partials[sz_class]);
      assert(slab->class == sz_class);
      fl->slab = slab;
    } else {
      return false;
    }
  } else {
    end_index =
        (int64_t)((fl->end_ptr - (uint64_t)slab->start)) / slab_sz(slab);
  }
  uint64_t maxbit = ((slab->end - slab->start)) / slab_sz(slab);
  uint64_t new_start;
  if (!find_next_bit(slab->markbits, maxbit, end_index + 1, true, &new_start)) {
    fl->slab = nullptr;
    [[clang::musttail]] return get_partial_range(sz_class, fl);
  }
  uint64_t new_end = maxbit - 1;
  find_next_bit(slab->markbits, maxbit, new_start + 1, false, &new_end);
  for (uint64_t i = new_start; i < new_end; i++) {
    assert(!bt(slab->markbits, i));
  }
  fl->start_ptr = (uint64_t)slab->start + new_start * slab_sz(slab);
  fl->end_ptr = (uint64_t)slab->start + new_end * slab_sz(slab);
  assert((uintptr_t)fl->start_ptr >= (uintptr_t)fl->slab->start);
  assert((uintptr_t)fl->end_ptr <= (uintptr_t)fl->slab->end);
  return true;
}

static uintptr_t memstart;
static uintptr_t memend;

void gc_init(void *stacktop_in) {
  uint64_t gc_virtual_space = PAGE_SIZE * PAGE_SIZE * 120;
  auto gc_space_env = getenv("GC_SPACE");
  if (gc_space_env) {
    gc_virtual_space = atoll(gc_space_env);
  }
  memstart = (intptr_t)mmap(nullptr, gc_virtual_space, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
  if ((intptr_t)memstart == -1) {
    printf("Can't alloc virtual space: %" PRIu64 "\n", gc_virtual_space);
    abort();
  }
  memend = memstart + gc_virtual_space;
  memstart = align(memstart, default_slab_size);
  alloc_table_init(&atable, memstart, memend);
  stacktop = stacktop_in;

  // Set defaults so we don't have to check for wrapping in
  // the fastpath.
  for (uint64_t i = 0; i < size_classes; i++) {
    freelist[i] = (freelist_s){default_slab_size, default_slab_size, nullptr};
    kv_init(partials[i]);
  }
  kv_init(roots);
  for (uint64_t i = 0; i < page_classes; i++) {
    kv_init(pages_free[i]);
  }
}

void gc_add_root(uint64_t *rootp) { kv_push(roots, rootp); }

void gc_pop_root(uint64_t const *rootp) {
#ifndef NDEBUG
  auto old_rootp = kv_pop(roots);
  assert(old_rootp == rootp);
#else
  kv_pop(roots);
#endif
}

typedef struct range {
  uint64_t *start;
  uint64_t *end;
} range;

static uint64_t totsize;
static kvec_t(range) markstack;

static void mark() {
  while (kv_size(markstack) > 0) {
    range r = kv_pop(markstack);
    //  Double check it is aligned.
    assert(((int64_t)r.start & 0x7) == 0);
    assert(((int64_t)r.end & 0x7) == 0);
    while (r.start < r.end) {
      uint8_t *val = (uint8_t *)*r.start;
      slab_info *slab;
      bool found = alloc_table_lookup(&atable, val, (void **)&slab);
      if (found && (slab != nullptr) && (val >= slab->start) &&
          (val < slab->end)) {
        // Find the start of the object
        if (list_empty(&slab->link)) {
          r.start++;
          continue;
        }
        uint64_t index =
            ((uint64_t)val - (uint64_t)slab->start) / slab_sz(slab);
        uint64_t base_ptr = (uint64_t)slab->start + (slab_sz(slab) * index);
        if (!bt(slab->markbits, index)) {
          totsize += slab_sz(slab);
          slab->marked += slab->class * 8;
          bts(slab->markbits, index);
          kv_push(markstack, ((range){(uint64_t *)base_ptr,
                                      (uint64_t *)(base_ptr + slab_sz(slab))}));
        }
      }
      r.start++;
    }
  }
}

static void merge_and_free_slab(slab_info *slab) {
  // TODO: actual merge.
  if (slab->class < size_classes) {
    slab->start -= mark_byte_cnt;
  }
  auto page_class = sz_to_page_class(slab->end - slab->start);
  if (page_class >= page_classes) {
    // Direct free
    alloc_table_set_range(&atable, nullptr, slab->start,
                          slab->end - slab->start);
    free(slab->start);
    free(slab);
    return;
  }
  init_list_head(&slab->link);
  kv_push(pages_free[page_class], slab);
}

static uint64_t collect_big = 0;
static bool next_force_full = false;
__attribute__((noinline, preserve_none)) static void gc_collect() {
  /* struct timespec start; */
  /* struct timespec end; */
  /* clock_gettime(CLOCK_MONOTONIC, &start); */
  bool collect_full = next_force_full;

#ifdef GENGC
  if (collect_big++ == 8) {
    collect_big = 0;
    collect_full = true;
  }
#else
  collect_full = true;
#endif

  // Init mark stack
  kv_init(markstack);

  // Clear marks
  list_head *itr;
  list_for_each(itr, &live_slabs) {
    slab_info *slab = container_of(itr, slab_info, link);

    if (collect_full) {
      totsize = 0;
      memset(slab->markbits, 0, sizeof(slab->markbits));
      slab->marked = 0;
      if (slab->class < size_classes) {
        uint64_t *logbits = (uint64_t *)(slab->start - mark_byte_cnt);
        memset(logbits, 0, mark_byte_cnt);
      }
    } else {

      // Remembered set analysis for sticky mark-bit sweeping
      // (generational mark-sweep).
      if (slab->class < size_classes) {
        // Small classes use a logbits area at the start of the
        // slab.
        uint64_t *logbits = (uint64_t *)(slab->start - mark_byte_cnt);
        assert(((uint64_t)logbits & (default_slab_size - 1)) == 0);
        uint64_t bit = 0;
        while (true) {
          uint64_t res;
          auto hasnext =
              find_next_bit(logbits, mark_byte_cnt * 8, bit, false, &res);
          if (!hasnext) {
            break;
          }
          uint64_t logptr = (uint64_t)logbits + (res * 8);
          uint64_t index = (logptr - (uint64_t)slab->start) / slab_sz(slab);
          // Only walk remembered set if the object it is in is already marked -
          // otherwise it will already traced if live.
          if (bt(slab->markbits, index)) {
            kv_push(markstack,
                    ((range){(uint64_t *)logptr, (uint64_t *)(logptr + 8)}));
          }

          bit = res + 1;
        }
        // Reset remembered set.
        memset(logbits, 0, mark_byte_cnt);
      } else {
        //  Large objects use a single bit, bit 0 in markbits
        if (bt(slab->markbits, 1)) {
          kv_push(markstack,
                  ((range){(uint64_t *)slab->start,
                           (uint64_t *)(slab->start + slab_sz(slab))}));
          // Reset markbit.
          btr(slab->markbits, 1);
        }
      }
    }
  }
  for (uint64_t i = 0; i < size_classes; i++) {
    kv_clear(partials[i]);
  }

  // Mark static roots
  for (uint64_t i = 0; i < kv_size(roots); i++) {
    auto root = kv_A(roots, i);
    kv_push(markstack, ((range){root, root + 1}));
  }

  // Mark stack
  uint64_t *sp = (uint64_t *)__builtin_frame_address(0);
  kv_push(markstack, ((range){sp, stacktop}));

  // Run mark loop.
  mark();

  // Sweep empty blocks.
  uint64_t freed_bytes = 0;
  /* uint64_t total_bytes = 0; */
  itr = live_slabs.next;
  while (!list_is_head(itr, &live_slabs)) {
    auto next_itr = itr->next;
    auto slab = container_of(itr, slab_info, link);
    assert(!list_empty(&slab->link));
    if (slab->marked == 0) {
      list_del(itr);
      merge_and_free_slab(slab);
      freed_bytes += slab->end - slab->start;
    } else {
      auto tot_size = slab->end - slab->start;
      /* if (slab->marked != tot_size) { */
      /* 	printf("Frag %i clss %i %% %f\n", slab->marked, slab->class,
       * 100.0*(double)(tot_size - slab->marked) / (double)tot_size); */
      /* } */
      if (slab->class < size_classes) {
        if (slab->marked < tot_size / 2) {
          kv_push(partials[slab->class], slab);
        }
      }
    }
    /* total_bytes += slab->end - slab->start; */
    itr = next_itr;
  }
  for (uint64_t i = 0; i < size_classes; i++) {
    freelist[i].start_ptr = default_slab_size;
    freelist[i].end_ptr = default_slab_size;
    freelist[i].slab = nullptr;
  }
  /* uint64_t live_bytes = total_bytes - freed_bytes; */

  // TODO: ideally we would have a running statistic
  // how many bytes we *expect* to be freed by a full collect vs.
  // a minor collection.
  //
  // earley is highly fragmented, but full GC's don't help.
  // paraffins needs lots of full GC's.
  if (collect_full && (next_collect < totsize)) {
    next_collect = totsize;
  }
  next_force_full = false;
  if (!collect_full && freed_bytes < next_collect / 2) {
    next_force_full = true;
  }

  kv_destroy(markstack);

  /* clock_gettime(CLOCK_MONOTONIC, &end); */
  /* auto rem_bytes = total_bytes - freed_bytes; */
  /* double time_taken = */
  /*     ((double)end.tv_sec - (double)start.tv_sec) * 1000.0; // sec to ms */
  /* time_taken += */
  /*     ((double)end.tv_nsec - (double)start.tv_nsec) / 1000000.0; // ns to ms
   */
  /* printf( */
  /* 	 "COLLECT %.3f ms, full %i, %li total %li, freed %li, free%% %f,
   * next_collect %li, totsize %li rembytes %li, frag %% %f\n", */
  /* 	 time_taken, collect_full, totsize, total_bytes, freed_bytes, 100.0 *
   * (double)freed_bytes / (double)total_bytes, next_collect, */
  /* 	 totsize, rem_bytes, */
  /* 	 100.0 * (double) (rem_bytes - totsize) / (double)rem_bytes); */
}

static slab_info *alloc_slab(uint64_t sz_class) {
  auto sz = sz_class < size_classes ? default_slab_size
                                    : align(sz_class * 8, default_slab_size);
  // Find page class: Choose next largest class to ensure we have enough room.
  // TODO: no need to increment if perfect size.
  auto page_class = sz_to_page_class(sz);
  sz = page_class_to_sz(page_class);

  // TODO: split the range here based on actual size.
  // TODO: check larger bins & split.
  if (page_class < page_classes && kv_size(pages_free[page_class])) {
    slab_info *free = kv_pop(pages_free[page_class]);
    if (free) {
      assert((int64_t)sz <= (free->end - free->start));
      free->class = sz_class;
      list_add(&free->link, &live_slabs);
      return free;
    }
  }

  slab_info *free = calloc(1, sizeof(slab_info));
  free->class = sz_class;
  init_list_head(&free->link);

  free->start = (uint8_t *)memstart;
  memstart += sz;
  if (memstart >= memend) {
    printf(
        "Out of memory.  Set virtual space explicitly with GC_SPACE env var\n");
    abort();
  }
  assert(0 == ((uint64_t)free->start & (default_slab_size - 1)));

  //memset(free->start, 0, sz);
  free->end = free->start + sz;
  list_add(&free->link, &live_slabs);

  alloc_table_set_range(&atable, free, free->start, free->end - free->start);
  return free;
}

NOINLINE __attribute__((preserve_most)) static void *
gc_alloc_slow(uint64_t sz) {
  if (collect_cnt >= next_collect) {
    collect_cnt = 0;
    gc_collect();
    return gc_alloc(sz);
  }
  assert((sz & 0x7) == 0);

  uint64_t sz_class = sz / 8;
  // It is a large slab.
  if (sz_class >= size_classes) {
    auto slab = alloc_slab(sz_class);
    collect_cnt += sz;
    return slab->start;
  }
  // It's in a small slab.
  if (!get_partial_range(sz_class, &freelist[sz_class])) {
    auto slab = alloc_slab(sz_class);
    // Leave room for logbits
    memset(slab->start, 0, mark_byte_cnt);
    slab->start += mark_byte_cnt;

    freelist[sz_class].start_ptr = (uint64_t)slab->start;
    freelist[sz_class].end_ptr = (uint64_t)slab->end;
    freelist[sz_class].slab = slab;
    collect_cnt += freelist[sz_class].end_ptr - freelist[sz_class].start_ptr;
  }
  return gc_alloc(sz);
}

void *gc_alloc(uint64_t sz) {
  assert((sz & 0x7) == 0);
  uint64_t sz_class = sz / 8;
  if (unlikely(sz_class >= size_classes)) {
    return gc_alloc_slow(sz);
  }
  auto fl = &freelist[sz_class];

  auto s = fl->start_ptr;
  auto start = fl->start_ptr + (sz_class * 8);
  if (unlikely(start > fl->end_ptr)) {
    return gc_alloc_slow(sz);
  }

  fl->start_ptr = start;
  return (void *)s;
}

void gc_log(uint64_t a) {
#ifdef GENGC
  slab_info *slab;
  if (!alloc_table_lookup(&atable, (void *)a, (void **)&slab)) {
    // It's in the static data section (probably).
    return;
  }

  if (likely(slab->class < size_classes)) {
    uint64_t *logbits = (uint64_t *)(a & ~(default_slab_size - 1));
    uint64_t addr = a & (default_slab_size - 1);
    bts(logbits, (addr / 8));
  } else {
    if (bt(slab->markbits, 0)) {
      bts(slab->markbits, 1);
    }
  }
#endif
}
