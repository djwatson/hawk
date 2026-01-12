#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

// Comment out to turn off generational GC.
// TODO re-enable after logging SET commands
// #define GENGC 1

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
#include "hawk.h"
#include "profiler.h"
#include "util/bitset.h"
#include "util/kvec.h"
#include "util/list.h"
#include "util/util.h"

// May be already defined.
#ifndef PAGE_SIZE
static constexpr uint64_t PAGE_SIZE = 1UL << 12;
#endif
static constexpr uint64_t default_slab_size = PAGE_SIZE * 4;
static uint64_t next_collect = 100000000;
static uint64_t collect_cnt = 0;
static alloc_table atable;

static uint64_t *stacktop;
static uintptr_t mem_base;
static uintptr_t memstart;
static uintptr_t memend;
static uint64_t mem_map_size;

uint64_t *gc_get_stack_top() { return stacktop; }

static void format_bytes(char *buf, size_t buf_sz, uint64_t bytes) {
  double val = bytes;
  const char *suffix = "B";
  bool exact = true;
  if (bytes >= (1ULL << 30)) {
    val = bytes / (double)(1ULL << 30);
    suffix = "GB";
    exact = false;
  } else if (bytes >= (1ULL << 20)) {
    val = bytes / (double)(1ULL << 20);
    suffix = "MB";
    exact = false;
  } else if (bytes >= (1ULL << 10)) {
    val = bytes / (double)(1ULL << 10);
    suffix = "KB";
    exact = false;
  }
  if (exact) {
    snprintf(buf, buf_sz, "%" PRIu64 "%s", bytes, suffix);
  } else {
    snprintf(buf, buf_sz, "%.1f%s", val, suffix);
  }
}

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

freelist_s freelist[size_classes];
static kvec_t(slab_info *) partials[size_classes];
static LIST_HEAD(live_slabs);
typedef struct root_range {
  const uint64_t *ptr;
  size_t len;
} root_range;

static kvec_t(root_range) roots;
static gc_scan_callback scan_callback;
static void *scan_data;

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
    class--;
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
  uint64_t new_end = maxbit;
  find_next_bit(slab->markbits, maxbit, new_start + 1, false, &new_end);
  for (uint64_t i = new_start; i < new_end; i++) {
    assert(!bt(slab->markbits, i));
  }
  fl->start_ptr = (uint64_t)slab->start + (new_start * slab_sz(slab));
  fl->end_ptr = (uint64_t)slab->start + (new_end * slab_sz(slab));
  assert((uintptr_t)fl->start_ptr >= (uintptr_t)fl->slab->start);
  assert((uintptr_t)fl->end_ptr <= (uintptr_t)fl->slab->end);
  return true;
}

void gc_init(void *stacktop_in) {
  // ~2GB, which is sufficient for every r7rs benchmark.
  uint64_t gc_virtual_space = PAGE_SIZE * PAGE_SIZE * 120;
  auto gc_space_env = getenv("GC_SPACE");
  if (gc_space_env) {
    gc_virtual_space = atoll(gc_space_env);
  }
  mem_base = (intptr_t)mmap(nullptr, gc_virtual_space, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
  if ((intptr_t)mem_base == -1) {
    printf("Can't alloc virtual space: %" PRIu64 "\n", gc_virtual_space);
    abort();
  }
  mem_map_size = gc_virtual_space;
  memstart = mem_base;
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

void gc_add_root(const uint64_t *rootp, size_t len) {
  kv_push(roots, ((root_range){.ptr = rootp, .len = len}));
}

void gc_remove_root(uint64_t const *rootp) {
  for (size_t i = 0; i < kv_size(roots); i++) {
    if (kv_A(roots, i).ptr == rootp) {
      kv_A(roots, i) = kv_A(roots, kv_size(roots) - 1);
      (void)kv_pop(roots);
      return;
    }
  }
#ifndef NDEBUG
  assert(!"Attempted to remove unknown GC root");
#endif
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void *gc_base_ptr(void *p) {
  slab_info *slab = nullptr;
  bool found = alloc_table_lookup(&atable, p, (void **)&slab);
  assert(found);
  assert(slab);
  assert(!list_empty(&slab->link));
  assert((uint8_t *)p >= slab->start);
  assert((uint8_t *)p < slab->end);
  uint64_t index = ((uint64_t)p - (uint64_t)slab->start) / slab_sz(slab);
  uint64_t base_ptr = (uint64_t)slab->start + (slab_sz(slab) * index);
  return (void *)base_ptr;
}

typedef struct range {
  const uint64_t *start;
  const uint64_t *end;
} range;

static uint64_t totsize;
static kvec_t(range) markstack;

static void gc_add_mark_root(const uint64_t *rootp, size_t len) {
  assert(rootp);
  assert(len >= 1);
  kv_push(markstack, ((range){rootp, rootp + len}));
}

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
          kv_push(markstack,
                  ((range){(const uint64_t *)base_ptr,
                           (const uint64_t *)(base_ptr + slab_sz(slab))}));
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
  struct timespec start;
  struct timespec end;
  profiler_set_in_gc(true);
  clock_gettime(CLOCK_MONOTONIC, &start);
  totsize = 0;
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
            kv_push(markstack, ((range){(const uint64_t *)logptr,
                                        (const uint64_t *)(logptr + 8)}));
          }

          bit = res + 1;
        }
        // Reset remembered set.
        memset(logbits, 0, mark_byte_cnt);
      } else {
        //  Large objects use a single bit, bit 0 in markbits
        if (bt(slab->markbits, 1)) {
          kv_push(markstack,
                  ((range){(const uint64_t *)slab->start,
                           (const uint64_t *)(slab->start + slab_sz(slab))}));
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
  for (size_t i = 0; i < kv_size(roots); i++) {
    auto root = kv_A(roots, i);
    if (root.ptr && root.len > 0) {
      kv_push(markstack, ((range){root.ptr, root.ptr + root.len}));
    }
  }
  if (scan_callback) {
    scan_callback(scan_data, gc_add_mark_root);
  }

  // Mark stack
  uint64_t *sp = (uint64_t *)__builtin_frame_address(0);
  kv_push(markstack, ((range){sp, stacktop}));

  // Run mark loop.
  mark();

  // Sweep empty blocks.
  uint64_t freed_bytes = 0;
  uint64_t total_bytes = 0;
  itr = live_slabs.next;
  while (!list_is_head(itr, &live_slabs)) {
    auto next_itr = itr->next;
    auto slab = container_of(itr, slab_info, link);
    assert(!list_empty(&slab->link));
    auto slab_bytes = slab->end - slab->start;
    total_bytes += slab_bytes;
    if (slab->marked == 0) {
      list_del(itr);
      merge_and_free_slab(slab);
      freed_bytes += slab_bytes;
    } else {
      /* if (slab->marked != slab_bytes) { */
      /* 	printf("Frag %i clss %i %% %f\n", slab->marked, slab->class,
       * 100.0*(double)(slab_bytes - slab->marked) / (double)slab_bytes); */
      /* } */
      if (slab->class < size_classes) {
        if (slab->marked < slab_bytes / 2) {
          kv_push(partials[slab->class], slab);
        }
      }
    }
    itr = next_itr;
  }
  for (uint64_t i = 0; i < size_classes; i++) {
    freelist[i].start_ptr = default_slab_size;
    freelist[i].end_ptr = default_slab_size;
    freelist[i].slab = nullptr;
  }

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

  clock_gettime(CLOCK_MONOTONIC, &end);
  auto live_bytes = total_bytes - freed_bytes;
  auto freed_pct =
      total_bytes == 0 ? 0.0
                       : 100.0 * (double)freed_bytes / (double)total_bytes;
  auto live_pct =
      live_bytes == 0 ? 0.0 : 100.0 * (double)totsize / (double)live_bytes;
  auto frag_pct =
      live_bytes == 0
          ? 0.0
          : 100.0 * (double)(live_bytes - totsize) / (double)live_bytes;
  double time_taken =
      ((double)end.tv_sec - (double)start.tv_sec) * 1000.0; // sec to ms
  time_taken +=
      ((double)end.tv_nsec - (double)start.tv_nsec) / 1000000.0; // ns to ms
  if (verbose) {
    char freed_buf[32];
    char total_buf[32];
    char live_buf[32];
    char next_buf[32];
    format_bytes(freed_buf, sizeof(freed_buf), freed_bytes);
    format_bytes(total_buf, sizeof(total_buf), total_bytes);
    format_bytes(live_buf, sizeof(live_buf), totsize);
    format_bytes(next_buf, sizeof(next_buf), next_collect);
    const char *mode = collect_full ? "full" : "partial";
    printf("COLLECT %.3f ms (%s) freed %s/%s (%.1f%%), live %s (%.1f%%), "
           "frag %.1f%%, next_collect %s\n",
           time_taken, mode, freed_buf, total_buf, freed_pct, live_buf, live_pct,
           frag_pct, next_buf);
  }
  profiler_set_in_gc(false);
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

  // memset(free->start, 0, sz);
  free->end = free->start + sz;
  list_add(&free->link, &live_slabs);

  alloc_table_set_range(&atable, free, free->start, free->end - free->start);
  return free;
}

NOINLINE __attribute__((preserve_most)) void *gc_alloc_slow(uint64_t sz) {
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
  assert(freelist[sz_class].start_ptr != freelist[sz_class].end_ptr);
  return gc_alloc(sz);
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

static void free_slab_info(slab_info *slab) {
  if (!slab) {
    return;
  }
  free(slab);
}

void gc_free(void) {
  kv_destroy(roots);
  for (uint64_t i = 0; i < size_classes; i++) {
    kv_destroy(partials[i]);
  }
  list_head *itr = live_slabs.next;
  while (!list_is_head(itr, &live_slabs)) {
    auto next_itr = itr->next;
    auto slab = container_of(itr, slab_info, link);
    list_del(itr);
    free_slab_info(slab);
    itr = next_itr;
  }
  for (uint64_t i = 0; i < page_classes; i++) {
    for (size_t j = 0; j < kv_size(pages_free[i]); j++) {
      free_slab_info(kv_A(pages_free[i], j));
    }
    kv_destroy(pages_free[i]);
  }
  alloc_table_free(&atable);
  if (mem_base) {
    munmap((void *)mem_base, mem_map_size);
    mem_base = 0;
    mem_map_size = 0;
  }
}
