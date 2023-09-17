#define _DEFAULT_SOURCE

#include "gc.h"
#include "bytecode.h"     // for const_table, const_table_sz
#include "ir.h"           // for reloc, trace_s, RELOC_ABS, RELOC_SYM_ABS
#include "symbol_table.h" // for sym_table, table, TOMBSTONE
#include "third-party/stb_ds.h"
#include "defs.h"
#include "types.h"    // for TAG_MASK, FORWARD_TAG, SYMBOL_TAG, symbol
#include <assert.h>   // for assert
#include <stdint.h>   // for uint8_t, int64_t
#include <stdio.h>    // for printf
#include <stdlib.h>   // for free, realloc
#include <string.h>   // for memcpy
#include <sys/mman.h> // for mprotect, mmap, PROT_NONE, PROT_READ, PROT...

#define auto __auto_type

extern bool verbose;

extern long *stack;
extern unsigned int stacksz;

static bool gc_enable = true;

uint8_t *alloc_ptr = NULL;
uint8_t *alloc_end = NULL;

long **pushed_roots = NULL;

void GC_push_root(long *root) { arrput(pushed_roots, root); }

void GC_pop_root(const long *root) {
  assert(arrlen(pushed_roots) != 0);
#ifdef NDEBUG
  arrpop(pushed_roots);
#else
  auto b = arrpop(pushed_roots);
  assert(b == root);
#endif
}

void GC_enable(bool en) { gc_enable = en; }

static bool is_forwarded(long obj) {
  auto *ptr = (long *)obj;
  return ((*ptr) & TAG_MASK) == FORWARD_TAG;
}

static void set_forward(long *ptr, void *to) {
  assert(((*ptr) & TAG_MASK) != FORWARD_TAG);
  *ptr = (long)to + FORWARD_TAG;
}

static long get_forward(long obj) {
  assert(is_forwarded(obj));
  auto *ptr = (long *)obj;
  // printf("Obj %p forwarded to %lx\n", ptr, (*ptr) - FORWARD_TAG);
  return (*ptr) - FORWARD_TAG;
}

size_t __attribute__((always_inline)) heap_object_size(long *obj) {
  auto type = *obj;
  assert((type * TAG_MASK) != FORWARD_TAG);
  switch (type) {
  case FLONUM_TAG:
    return sizeof(flonum_s);
  case STRING_TAG: {
    auto *str = (vector_s *)obj;
    return (str->len >> 3) * sizeof(char) + 16 + 1 /* null tag */;
  }
  case SYMBOL_TAG:
    return sizeof(symbol);
  case CONT_TAG:
  case VECTOR_TAG: {
    auto *vec = (vector_s *)obj;
    return (vec->len >> 3) * sizeof(long) + 16;
  }
  case CONS_TAG:
    return sizeof(cons_s);
  case CLOSURE_TAG: {
    auto *clo = (closure_s *)obj;
    return (clo->len >> 3) * sizeof(long) + 16;
  }
  case PORT_TAG:
    return sizeof(port_s);
  default:
    printf("Unknown heap object: %li\n", type);
    assert(false);
    return -1;
  }
}

size_t align(size_t sz) { return (sz + 7) & (~TAG_MASK); }

void *copy(long *obj) {
  // printf("COPY obj %p, type %li\n", obj, *obj);
  size_t sz = heap_object_size(obj);
  auto *res = alloc_ptr;
  // printf("Memcpy %li bytes to %p\n", sz, res);
  memcpy(res, obj, sz);
  set_forward(obj, res);
  alloc_ptr += align(sz);
  assert(alloc_ptr < alloc_end);
  return res;
}

void visit(long *field) {
  auto from = *field;
  auto tag = from & TAG_MASK;
  //  printf("TAG %li\n", tag);
  if (tag == PTR_TAG || tag == FLONUM_TAG || tag == CONS_TAG ||
      tag == CLOSURE_TAG || tag == SYMBOL_TAG) {
    auto p = from & (~TAG_MASK);
    //     printf("Visiting ptr field %lx\n", p);
    auto to = is_forwarded(p) ? get_forward(p) : (long)copy((long *)p);
    //     printf("Visiting ptr field %lx moved to %lx \n", p, to);
    *field = to + tag;
  }
}

void trace_heap_object(long *obj) {
  // printf("Trace heap obj %p\n", obj);
  auto type = *obj;
  assert((type & TAG_MASK) != FORWARD_TAG);
  switch (type) {
  case FLONUM_TAG:
  case STRING_TAG:
    break;
  case SYMBOL_TAG: {
    auto *sym = (symbol *)obj;
    // temporarily add back the tag
    visit(&sym->name);
    visit(&sym->val);
    break;
  }
  case CONT_TAG:
  case VECTOR_TAG: {
    auto *vec = (vector_s *)obj;
    for (long i = 0; i < (vec->len >> 3); i++) {
      visit(&vec->v[i]);
    }
    break;
  }
  case CONS_TAG: {
    auto *cons = (cons_s *)obj;
    visit(&cons->a);
    visit(&cons->b);
    break;
  }
  case CLOSURE_TAG: {
    auto *clo = (closure_s *)obj;
    // Note start from 1: first field is bcfunc* pointer.
    for (long i = 1; i < (clo->len >> 3); i++) {
      visit(&clo->v[i]);
    }
    break;
  }
  case PORT_TAG:
    break;
  default:
    printf("Unknown heap object: %li\n", type);
    assert(false);
  }
}

// Static roots are the stack - stacksz,
// the symbol table,
// and the constant table.
// and symbols?????? shit
extern trace_s *trace;
extern trace_s **traces;
extern long *symbols;

static void visit_trace(trace_s *t) {
  for (size_t i = 0; i < arrlen(t->consts); i++) {
    if (t->consts[i]) {
      // printf("Visit const ");
      // print_obj(t->consts[i]);
      // printf("\n");
      visit(&t->consts[i]);
    }
  }
  for (uint64_t i = 0; i < arrlen(t->relocs); i++) {
    auto reloc = &t->relocs[i];
    auto old = reloc->obj;
    visit(&reloc->obj);
    if (reloc->obj != old) {
      switch (reloc->type) {
      case RELOC_ABS: {
	int64_t v = reloc->obj;
	memcpy((int64_t*)(reloc->offset - 8), &v, sizeof(int64_t));
        break;
      }
      case RELOC_SYM_ABS: {
        auto *sym = (symbol *)(reloc->obj - SYMBOL_TAG);
	int64_t v = (int64_t)&sym->val;
	memcpy((int64_t*)(reloc->offset - 8), &v, sizeof(int64_t));
        break;
      }
      default: {
        printf("Unknown reloc: %i\n", reloc->type);
        assert(false);
      }
      }
    }
  }
}
//
// Currently functions aren't GC'd.
static void trace_roots() {
  // printf("Scan symbols from readbc...%li\n", symbols.size());
  for (uint64_t i = 0; i < arrlen(symbols); i++) {
    visit(&symbols[i]);
  }

  // printf("Scan GC pushed roots...%li\n", pushed_roots.size()) ;
  for (uint64_t i = 0; i < arrlen(pushed_roots); i++) {
    visit(pushed_roots[i]);
  }

  // printf("Scan stack...%u\n", stacksz);
  for (size_t i = 0; i < stacksz; i++) {
    if (stack[i] != 0) {
      visit(&stack[i]);
    }
  }
  // printf("Scan constant table... %li\n", const_table_sz);
  for (size_t i = 0; i < const_table_sz; i++) {
    if (const_table[i] != 0) {
      visit(&const_table[i]);
    }
  }
  // printf("Scan symbol table...\n");
  for (size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[i];
    if (*cur != NULL && *cur != TOMBSTONE) {
      auto *tmp = (long *)&sym_table->entries[i];
      *tmp += SYMBOL_TAG;
      visit(tmp);
      *tmp -= SYMBOL_TAG;
    }
  }

// Scan traces
#ifdef JIT
  for (uint64_t i = 0; i < arrlen(traces); i++) {
    auto *t = traces[i];
    // printf("Visit trace %i\n", cnt++);
    visit_trace(t);
  }
  // Scan currently in-progress trace
  if (trace != NULL) {
    // printf("Visit in progress trace\n");
    visit_trace(trace);
  }
#endif
}

// static constexpr size_t page_cnt = 6000; // Approx 25 mb.
// static constexpr size_t page_cnt = '12000; // Approx 50 mb.
// static constexpr size_t page_cnt = 30000; // Approx 125 mb.
// static constexpr size_t page_cnt = 120000; // Approx 500 mb.
// size_t page_cnt = 500000; // Approx 2GB
extern size_t page_cnt;
size_t alloc_sz;
uint8_t *to_space = NULL;
uint8_t *from_space = NULL;
static bool embiggen = false;

static void GC_deinit() {
  arrfree(pushed_roots);
}

EXPORT void GC_init() {
  alloc_sz = 4096 * page_cnt;
  from_space = (uint8_t *)mmap(NULL, alloc_sz * 2, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(from_space);
  alloc_ptr = from_space;
  alloc_end = alloc_ptr + alloc_sz;
  to_space = alloc_ptr + alloc_sz;
#ifndef NDEBUG
  mprotect(to_space, alloc_sz, PROT_NONE);
#endif
  atexit(&GC_deinit);
}

#ifdef PROFILER
bool in_gc = false;
#endif
__attribute__((noinline)) void *GC_malloc_slow(size_t sz) {
  void *res;
#ifdef PROFILER
  in_gc = true;
#endif

  // Slowpath.
  if (sz >= alloc_sz) {
    embiggen = true;
  }
  // printf("Collecting...\n");

  assert(gc_enable || alloc_end == NULL);
#ifndef NDEBUG
  mprotect(to_space, alloc_sz, PROT_READ | PROT_WRITE);
#endif
  // flip
  // alloc_ptr = (uint8_t*)malloc(alloc_sz);
  void* to_unmap = NULL;
  if (embiggen) {
    to_unmap = from_space < to_space ? from_space : to_space;
    alloc_sz *= 2;
    if (verbose) {
      printf("Doubling space to %liMB\n", alloc_sz/1000000);
    }
    from_space = (uint8_t *)mmap(NULL, alloc_sz * 2, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(from_space);
    alloc_ptr = from_space;
    to_space = alloc_ptr + alloc_sz;
  } else {
    alloc_ptr = to_space;
    to_space = from_space;
    from_space = alloc_ptr;
  }

  alloc_end = alloc_ptr + alloc_sz;

  auto *scan = alloc_ptr;
  trace_roots();
  // printf("Cheney scan... %p %p\n", scan, alloc_ptr);
  while (scan < alloc_ptr) {
    auto scan_sz = heap_object_size((long *)scan);
    trace_heap_object((long *)scan);
    scan += align(scan_sz);
  }
  if (verbose) {
    printf("...Done collect, in use %li, %.2f%% of %liMB\n",
           alloc_ptr - from_space,
           ((double)(alloc_ptr - from_space)) / (double)alloc_sz * 100.0,
           alloc_sz / 1000 / 1000);
  }
  if (!to_unmap && (alloc_ptr - from_space) >= (alloc_sz / 2)) {
    // Next round, mmap a new space.
    embiggen = true;
  }

  if (to_unmap) {
    embiggen = false;
    auto r = munmap(to_unmap, alloc_sz / 2);
    if (r) {
      printf("Unmap error\n");
    }
  }

  res = alloc_ptr;
  alloc_ptr += sz;
  if (alloc_ptr >= alloc_end) {
    embiggen = true;
    return GC_malloc_slow(sz);
  }
#ifndef NDEBUG
  mprotect(to_space, alloc_sz, PROT_NONE);
#endif

#ifdef PROFILER
  in_gc = false;
#endif

  return res;
}

__attribute__((always_inline)) void *GC_malloc_no_collect(size_t sz) {
  sz = (sz + 7) & (~TAG_MASK);
  assert((sz & TAG_MASK) == 0);
  auto *res = alloc_ptr;
  alloc_ptr += sz;
  if (alloc_ptr < alloc_end) {
    return res;
  }
  return NULL;
}
__attribute__((always_inline)) void *GC_malloc(size_t sz) {
  sz = (sz + 7) & (~TAG_MASK);
  assert((sz & TAG_MASK) == 0);
  auto *res = alloc_ptr;
  alloc_ptr += sz;
  if (alloc_ptr < alloc_end) {
    return res;
  }
  return GC_malloc_slow(sz);
}

void *GC_realloc(void *ptr, size_t sz) {
  // TODO zero-mem
  return realloc(ptr, sz);
}

void GC_free(void *ptr) { free(ptr); }
