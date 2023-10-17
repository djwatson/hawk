// Copyright 2023 Dave Watson

#define _DEFAULT_SOURCE

#include "gc.h"

#include <assert.h> // for assert
#include <inttypes.h>
#include <stdint.h>   // for uint8_t, int64_t
#include <stdio.h>    // for printf
#include <stdlib.h>   // for free, realloc
#include <string.h>   // for memcpy
#include <sys/mman.h> // for mprotect, mmap, PROT_NONE, PROT_READ, PROT...

#include "bytecode.h" // for const_table, const_table_sz
#include "defs.h"
#include "ir.h"           // for reloc, trace_s, RELOC_ABS, RELOC_SYM_ABS
#include "symbol_table.h" // for sym_table, table, TOMBSTONE
#include "third-party/stb_ds.h"
#include "types.h" // for TAG_MASK, FORWARD_TAG, SYMBOL_TAG, symbol

/*
An RC-immix style GC.  Like many other immix variants though, we munge blocks&
lines a bit.

hawk's VM: exact, we always know on the stack what is a pointer and what isn't.
However, we may point to stale data, so we need to clear any 'unused' stack
portions each GC.

Notes:
  I tried not-copying at all for nursury, and it seemed to be *worse* due to
locality issues, even if GC stops were shorter.

  Full GC's almost never happen assuming small enough blocks (~256k),
fragmentation never really exceeds 20%. Additionally, there are almost no cycles
generated, except for very small heaps (<50mb).

  However, having small blocks, while not collecting until X bytes
  later, is *very* important.  Currently root scanning is expensive
  for large numbers of traces, and also the less we scan, the less we
  have to copy and RC.

  Currently, 256kB 'blocks' and 64MB collect frequency seems to be best.
 */

extern bool verbose;

extern gc_obj *stack;
extern gc_obj *stack_top;
extern gc_obj *frame_top;

static uint64_t gc_alloc = 0;
static uint64_t gc_dalloc = 0;
static uint64_t gc_large = 0;

uint8_t *alloc_start = NULL;
uint8_t *alloc_ptr = NULL;
uint8_t *alloc_end = NULL;

typedef struct {
  void *key;
} lalloc;

lalloc *large_allocs = NULL;

gc_obj **pushed_roots = NULL;

typedef struct {
  uint64_t offset;
  uint64_t addr;
} log_item;

#define COLLECT_SIZE (1024UL * 1024 * 32)
#define ALLOC_SZ_LOG 18
#define ALLOC_SZ (1UL << ALLOC_SZ_LOG)
#define ALLOC_SZ_MASK (ALLOC_SZ - 1)

size_t align(size_t sz) { return (sz + 7) & (~TAG_MASK); }
#define MARK_SZ (((ALLOC_SZ / 64) + 8) & ~8)
typedef struct {
  uint64_t cnt;
  uint8_t marks[MARK_SZ];
  uint8_t data[];
} gc_block;

static void block_bts(gc_block *block, void *ptr) {
  uint64_t loc = (uint64_t)ptr;
  uint64_t bit = (loc - (uint64_t)block->data) / 8;
  auto word = bit / 8;
  auto b = bit % 8;
  assert(word < MARK_SZ);
  block->marks[word] |= 1UL << b;
}
static bool block_bt(gc_block *block, void *ptr) {
  uint64_t loc = (uint64_t)ptr;
  uint64_t bit = (loc - (uint64_t)block->data) / 8;
  auto word = bit / 8;
  auto b = bit % 8;
  assert(word < MARK_SZ);
  return block->marks[word] & (1UL << b);
}

static gc_block **gc_blocks = NULL;
static gc_block **free_gc_blocks = NULL;

static log_item *log_buf = NULL;
static gc_obj **cur_increments = NULL;
static gc_obj *next_decrements = NULL;
static gc_obj *cur_decrements = NULL;

static void scan_log_buf(void (*add_increment)(gc_obj *));

static gc_block *alloc_gc_block() {
  gc_alloc += ALLOC_SZ;
  if (arrlen(free_gc_blocks)) {
    return arrpop(free_gc_blocks);
  }
  void *res;
  if (posix_memalign(&res, ALLOC_SZ, ALLOC_SZ)) {
    printf("posix_memalign error\n");
    exit(-1);
  }
  gc_block *mem = res;
  arrput(gc_blocks, mem);
  mem->cnt = 0;
  return mem;
}

static void put_gc_block(gc_block *mem) {
  assert((uint8_t *)mem != alloc_start);
  gc_alloc -= ALLOC_SZ;
  assert(mem->cnt == 0);
  arrput(free_gc_blocks, mem);
}

static bool is_ptr_type(gc_obj obj) {
  auto type = get_tag(obj);
  if (type == PTR_TAG || type == FLONUM_TAG || type == CONS_TAG ||
      type == VECTOR_TAG || type == CLOSURE_TAG || type == SYMBOL_TAG) {
    return true;
  }
  return false;
}

void GC_push_root(gc_obj *root) { arrput(pushed_roots, root); }

void GC_pop_root(const gc_obj *root) {
  (void)root;
  assert(arrlen(pushed_roots) != 0);
#ifdef NDEBUG
  (void)arrpop(pushed_roots);
#else
  auto b = arrpop(pushed_roots);
  assert(b == root);
#endif
}

static const uint64_t FORWARD = 0xffffffffffffffff;

static bool is_forwarded(void *obj) {
  uint64_t *ptr = obj;
  return *ptr == FORWARD;
}

static void set_forward(void *ptr, void *to) {
  uint64_t *lptr = ptr;
  assert(lptr[0] != FORWARD);
  lptr[0] = FORWARD;
  lptr[1] = (uint64_t)to;
}

static void *get_forward(void *obj) {
  assert(is_forwarded(obj));
  void **ptr = obj;
  return ptr[1];
}

static gc_block *cur_copy_block = NULL;
static uint8_t *copy_alloc_ptr = NULL;
static uint8_t *copy_alloc_end = NULL;
static bool in_nursury(void *to) {
  uint8_t *to_p = to;
  return (to_p >= alloc_start) && (to_p < alloc_end);
}

static void *copy_obj(void *obj) {
  // printf("COPY obj %p, type %li\n", obj, *obj);
  size_t sz = align(heap_object_size(obj));
  assert(in_nursury(obj));
  if (sz > ALLOC_SZ - sizeof(gc_block)) {
    // Move to large alloc.
    void *res;
    if (posix_memalign(&res, ALLOC_SZ, sz)) {
      abort();
    }
    memcpy(res, obj, sz);
    gc_large += sz;
    set_forward(obj, res);
    return res;
  }
  if (copy_alloc_ptr + sz >= copy_alloc_end) {
    assert(cur_copy_block == NULL || cur_copy_block->cnt != 0);
    if (cur_copy_block) {
      // Prevent from being collected prematurely.
      cur_copy_block->cnt--;
    }
    cur_copy_block = alloc_gc_block();
    copy_alloc_ptr = &cur_copy_block->data[0];
    copy_alloc_end = copy_alloc_ptr + ALLOC_SZ - sizeof(gc_block);
    assert(copy_alloc_ptr + sz < copy_alloc_end);
    cur_copy_block->cnt++;
  }
  auto res = copy_alloc_ptr;
  gc_dalloc += sz;
  copy_alloc_ptr += sz;
  cur_copy_block->cnt++;
  // printf("Memcpy %li bytes to %p\n", sz, res);
  memcpy(res, obj, sz);
  set_forward(obj, res);
  return res;
}

static void visit_cb(gc_obj *field, void *ctx) {
  gc_obj ***lst = ctx;
  if (is_ptr_type(*field)) {
    arrput(*lst, field);
  }
}
static bool fully_trace = false;
static void clear_block_marks() {
  for (uint64_t i = 0; i < arrlen(gc_blocks); i++) {
    auto block = gc_blocks[i];
    block->cnt = 0;
    if (cur_copy_block == block) {
      block->cnt++;
    }
    memset(block->marks, 0, sizeof(block->marks));
  }
  gc_dalloc = 0;
}

static inline gc_block *get_gc_block(void *ptr) {
  return (gc_block *)((uint64_t)ptr & ~ALLOC_SZ_MASK);
}
static void full_trace(gc_obj *start_field) {
  arrpush(cur_increments, start_field);
  do {
    gc_obj *field = arrpop(cur_increments);
    auto from = *field;
    auto tag = get_tag(from);
    if (!is_ptr_type(from)) {
      continue;
    }
    auto p = to_raw_ptr(from);
    auto to = is_forwarded(p) ? get_forward(p) : p;
    // printf("TAG %li\n", tag);
    // printf("Visiting ptr field %lx\n", p);
    auto block = get_gc_block(to);
    if (to == block) {
      gc_dalloc += heap_object_size(to);
      continue;
    }
    if (block_bt(block, to)) {
      RC_FIELD(to)++;
      // printf("INC %p to %i\n", to, ((uint32_t*)to)[1]);
      // assert(to < (long)alloc_start || to >= (long)alloc_end);
    } else {
      // assert(to >= (long)alloc_start && to < (long)alloc_end);
      //  If RC is 0.
      to = copy_obj(p);
      block = get_gc_block(to);
      block_bts(block, to);
      RC_FIELD(to) = 1;
      // printf("INC %p to %i (0)\n", to, ((uint32_t*)to)[1]);
      //  Need to recursively visit all fields
      trace_heap_object(to, visit_cb, &cur_increments);
    }
    *field = tag_void(to, tag);
  } while (arrlen(cur_increments));
}

static void sweep_large_allocs() {
  for (uint32_t i = 0; i < hmlen(large_allocs); i++) {
    if (RC_FIELD(large_allocs[i].key) == 0) {
      free(large_allocs[i].key);
    }
  }
  hmfree(large_allocs);
}
NOINLINE static void sweep_free_blocks() {
  gc_alloc = 0;
  arrsetlen(free_gc_blocks, 0);
  for (uint64_t i = 0; i < arrlen(gc_blocks); i++) {
    auto block = gc_blocks[i];
    if (block->cnt == 0) {
      put_gc_block(block);
    }
    gc_alloc += ALLOC_SZ;
  }
}
static void visit(gc_obj *start_field) {
  arrpush(cur_increments, start_field);
  do {
    gc_obj *field = arrpop(cur_increments);
    auto from = *field;
    auto tag = get_tag(from);
    if (!is_ptr_type(from)) {
      continue;
    }
    auto p = to_raw_ptr(from);
    auto to = is_forwarded(p) ? get_forward(p) : p;
    // printf("TAG %li\n", tag);
    // printf("Visiting ptr field %lx\n", p);
    if (in_nursury(to)) {
      assert(RC_FIELD(to) == 0);
      // If RC is 0.
      to = copy_obj(p);
      RC_FIELD(to)++;
      // printf("INC %p to %i (0)\n", to, ((uint32_t*)to)[1]);
      //  Need to recursively visit all fields
      trace_heap_object(to, visit_cb, &cur_increments);
    } else {
      RC_FIELD(to)++;
      // printf("INC %p to %i\n", to, ((uint32_t*)to)[1]);
      assert(!in_nursury(to));
    }
    //     printf("Visiting ptr field %lx moved to %lx \n", p, to);
    *field = tag_void(to, tag);
  } while (arrlen(cur_increments));
}

// Static roots are the stack - stacksz,
// the symbol table,
// and the constant table.
// and symbols?????? shit
extern trace_s *trace;
extern trace_s **traces;
extern gc_obj *symbols;

typedef void (*add_root_cb)(gc_obj *root);
static void visit_trace(trace_s *t, add_root_cb add_root) {
  for (size_t i = 0; i < arrlen(t->consts); i++) {
    if (is_ptr_type(t->consts[i])) {
      add_root(&t->consts[i]);
    }
  }
  for (uint64_t i = 0; i < arrlen(t->relocs); i++) {
    auto cur_reloc = &t->relocs[i];
    auto old = cur_reloc->obj;
    add_root(&cur_reloc->obj);
    if (cur_reloc->obj.value == old.value) {
      continue;
    }

    switch (cur_reloc->type) {
    case RELOC_ABS: {
      int64_t v = cur_reloc->obj.value;
      memcpy((int64_t *)(cur_reloc->offset - 8), &v, sizeof(int64_t));
      break;
    }
    case RELOC_ABS_NO_TAG: {
      int64_t v = cur_reloc->obj.value;
      v &= ~TAG_MASK;
      memcpy((int64_t *)(cur_reloc->offset - 8), &v, sizeof(int64_t));
      break;
    }
    case RELOC_SYM_ABS: {
      auto sym = to_symbol(cur_reloc->obj);
      int64_t v = (int64_t)&sym->val;
      memcpy((int64_t *)(cur_reloc->offset - 8), &v, sizeof(int64_t));
      break;
    }
    }
  }
}

static void trace_jit_roots(add_root_cb add_root) {
  // Scan traces
#ifdef JIT
  for (uint64_t i = 0; i < arrlen(traces); i++) {
    auto t = traces[i];
    // printf("Visit trace %i\n", cnt++);
    visit_trace(t, add_root);
  }
  // Scan currently in-progress trace
  if (trace != NULL) {
    // printf("Visit in progress trace\n");
    visit_trace(trace, add_root);
  }
#endif
}
//
// Currently functions aren't GC'd.
static void trace_roots(add_root_cb add_root) {
  // printf("Scan symbols from readbc...%li\n", arrlen(symbols));
  for (uint64_t i = 0; i < arrlen(symbols); i++) {
    add_root(&symbols[i]);
  }

  // printf("Scan GC pushed roots...%li\n", arrlen(pushed_roots));
  for (uint64_t i = 0; i < arrlen(pushed_roots); i++) {
    add_root(pushed_roots[i]);
  }

  // printf("Scan stack...%u\n", stack_top - stack);
  for (gc_obj *sp = stack; sp < stack_top; sp++) {
    if (is_ptr_type(*sp)) {
      add_root(sp);
    }
  }

  /* This is required because the stack isn't fully acurate:
   * CALL leaves a hole for the return address, and top-of-stack tracking
   * may be off by one, and not all instructions have top of stack tracking.
   *
   * The issue is if we only GC to the top of the stack, and junk left on the
   * stack may end up in a hole or used accidentally in top of stack off-by-one.
   * Just zero it out instead of implementing perfect tracking, or GC frame
   * emission in the compiler or something more complicated. If the remaining
   * stack is huge here, we may want to shrink it anyway?
   */
  memset(stack_top + 1, 0, ((uint64_t)frame_top - (uint64_t)(stack_top + 1)));
  // printf("Scan constant table... %li\n", const_table_sz);
  for (size_t i = 0; i < const_table_sz; i++) {
    if (is_ptr_type(const_table[i])) {
      add_root(&const_table[i]);
    }
  }
  // printf("Scan symbol table...\n");
  symbol_table_for_each(add_root);

  trace_jit_roots(add_root);
}

static struct {
  int traces;
  int full_traces;
} gc_stats = {0, 0};
static void GC_deinit() {
  /* arrfree(pushed_roots); */
  /* munmap(alloc_start, alloc_sz); */
  if (verbose) {
    printf("GC's %i Full traces %i (%.02f)\n", gc_stats.traces,
           gc_stats.full_traces,
           gc_stats.traces
               ? ((double)gc_stats.full_traces / (double)gc_stats.traces) *
                     100.0
               : 0);
  }
}

EXPORT void GC_init() {
  atexit(&GC_deinit);
  alloc_start = malloc(COLLECT_SIZE);
  alloc_ptr = alloc_start;
  alloc_end = alloc_start + COLLECT_SIZE;
}

static void trace2_cb(gc_obj *obj, void *ctx) {
  gc_obj **lst = ctx;
  arrput(*lst, *obj);
}
static int64_t trace2(gc_obj **lst) {
  int64_t gc_freed = 0;
  while (arrlen(*lst)) {
    auto item = arrpop(*lst);
    auto ptr = to_raw_ptr(item);
    if (!is_ptr_type(item)) {
      continue;
    }
    assert(!in_nursury(ptr));
    // printf("DEC %p to %i\n", ptr, ((uint32_t*)ptr)[1]);
    if (--RC_FIELD(ptr)) {
      continue;
    }

    // Recursive decrement
    auto sz = heap_object_size(ptr);
    trace_heap_object(ptr, trace2_cb, lst);
    auto block = get_gc_block(ptr);
    if (block == ptr) {
      // printf("Free %p\n", ptr);
      (void)hmdel(large_allocs, block);
      free(block);
      // unlink
    } else {
      gc_dalloc -= sz;
      if (--block->cnt == 0) {
        put_gc_block(block);
      }
    }
  }
  return gc_freed;
}

static void add_root(gc_obj *root) {
  full_trace(root);
  // Must reload root in case it was forwarded.
  arrput(next_decrements, *root);
}

static void add_root2(gc_obj *root) {
  visit(root);
  arrput(next_decrements, *root);
}

static void add_increment2(gc_obj *root) {
  gc_obj obj = *root;
  if (is_ptr_type(obj)) {
    visit(root);
  }
}

#ifdef PROFILER
bool in_gc = false;
#endif
NOINLINE void GC_collect() {
#ifdef PROFILER
  in_gc = true;
#endif
  /* for(uint64_t i = 0; i < arrlen(next_decrements); i++) { */
  /*   printf("Will dec %p\n", next_decrements[i]); */
  /* } */

  assert(arrlen(cur_increments) == 0);
  assert(arrlen(cur_decrements) == 0);
  // swap cur and next decrements.
  {
    auto tmp = cur_decrements;
    cur_decrements = next_decrements;
    next_decrements = tmp;
  }

  // Find all roots, add to cur_increments, and increment them.
  // Potentially copying them out of nursery.
  // printf("Trace roots...\n");

  // Scan log buf, adding to cur_increments
  //  printf("Scan log buf...\n");
  // Run increments
  // printf("Run increments...\n");
  gc_stats.traces++;
  if (fully_trace) {
    clear_block_marks();
    trace_roots(&add_root);
    // scan_log_buf(&add_increment);
    // TODO(djwatson) large object space?
    arrsetlen(log_buf, 0);
    // sweep_free_blocks();
    gc_stats.full_traces++;
  } else {
    trace_roots(&add_root2);
    scan_log_buf(&add_increment2);
  }
  arrsetlen(cur_increments, 0);
  // Run *last* iteration's decrements.
  // printf("Run %li decrements...\n", arrlen(cur_decrements));
  if (!fully_trace) {
    trace2(&cur_decrements);
  }
  arrsetlen(cur_decrements, 0);
  // printf("Done\n");

  sweep_large_allocs();
  sweep_free_blocks();
  double ratio = ((double)gc_dalloc / (double)gc_alloc) * 100.0;
  if (verbose) {
    printf("Heap sz: %" PRIu64 " alloced: %" PRIu64 " ratio: %.02f full: %i\n",
           gc_alloc, gc_dalloc, ratio, fully_trace);
  }
  arrsetlen(log_buf, 0);

  auto can_auto_adjust = (arrlen(gc_blocks) - arrlen(free_gc_blocks)) > 10;

  if (!(can_auto_adjust && ratio < 90.0)) {
    fully_trace = false;
  }

  alloc_ptr = alloc_start;
#ifdef PROFILER
  in_gc = false;
#endif
}

NOINLINE void *GC_malloc_slow(size_t sz) {
  if (align(sz) >= (ALLOC_SZ - sizeof(gc_block))) {
    if (gc_large > COLLECT_SIZE) {
      GC_collect();
      // printf("Collect\n");
      gc_large = 0;
    }
    void *res;
    if (posix_memalign(&res, ALLOC_SZ, align(sz))) {
      abort();
    }
    hmputs(large_allocs, (lalloc){res});
    // printf("Alloc %p\n", res);
    gc_large += align(sz);
    return res;
  }

  GC_collect();

  return GC_malloc(sz);
}

void *GC_malloc_no_collect(size_t sz);

void *GC_malloc(size_t sz);

#define LOG_OBJ_HEADER 0xffffffffffffffff
static void scan_log_buf(void (*add_increment)(gc_obj *)) {
  for (uint64_t i = 0; i < arrlen(log_buf);) {
    auto cur = log_buf[i];
    assert(cur.offset == LOG_OBJ_HEADER);
    auto addr = cur.addr;
    RC_FIELD(addr) &= ~LOGGED_MARK;

    i++;
    cur = log_buf[i];
    while (cur.offset != LOG_OBJ_HEADER) {
      auto field = (gc_obj *)(addr + cur.offset);
      auto v = *field;
      if (is_ptr_type(v)) {
        // printf("Add log increments: %p\n", *field);
        add_increment(field);
      }
      v = (gc_obj){.value = cur.addr};
      if (is_ptr_type(v)) {
        // printf("Add log decrements: %p\n", v);
        arrput(cur_decrements, v);
      }
      i++;
      if (i >= arrlen(log_buf)) {
        break;
      }
      cur = log_buf[i];
    }
  }
}

static void maybe_log(gc_obj *v_p, void *c) {
  auto v = *v_p;
  uint64_t addr = (uint64_t)c;
  arrput(log_buf, ((log_item){(uint64_t)v_p - addr, v.value}));
}

NOINLINE void GC_log_obj_slow(void *obj) {
  RC_FIELD(obj) |= LOGGED_MARK;
  arrput(log_buf, ((log_item){LOG_OBJ_HEADER, (uint64_t)obj}));

  trace_heap_object(obj, maybe_log, obj);
}

void GC_log_obj(void *ptr);
