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
#define unlikely(x) __builtin_expect(!!(x), 0)

extern bool verbose;

extern long *stack;
extern long* stack_top;
extern long* frame_top;

static bool gc_enable = true;
static long gc_alloc = 0;

uint8_t *alloc_start = NULL;
uint8_t *alloc_ptr = NULL;
uint8_t *alloc_end = NULL;

long **pushed_roots = NULL;

static const uint32_t LOGGED_MARK = (1UL << 31);

typedef struct {
  uint64_t offset;
  uint64_t addr;
} log_item;

static log_item* log_buf = NULL;
static long* cur_increments = NULL;
static long* next_decrements = NULL;
static long* cur_decrements = NULL;

static void scan_log_buf();

bool is_ptr_type(long obj) {
  auto type = obj & TAG_MASK;
  if (type == PTR_TAG || type == FLONUM_TAG || type == CONS_TAG ||
      type == CLOSURE_TAG || type == SYMBOL_TAG) {
    return true;
  }
  return false;
}

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
  return ((ptr[0]) & TAG_MASK) == FORWARD_TAG;
}

static void set_forward(long *ptr, void *to) {
  assert(((ptr[0]) & TAG_MASK) != FORWARD_TAG);
  ptr[0] = (long)to + FORWARD_TAG;
}

static long get_forward(long obj) {
  assert(is_forwarded(obj));
  auto *ptr = (long *)obj;
  // printf("Obj %p forwarded to %lx\n", ptr, (*ptr) - FORWARD_TAG);
  return (ptr[0]) - FORWARD_TAG;
}

size_t align(size_t sz) { return (sz + 7) & (~TAG_MASK); }

static long alloced = 0;
void *copy(long *obj) {
  // printf("COPY obj %p, type %li\n", obj, *obj);
  size_t sz = heap_object_size(obj);
  auto *res = malloc(sz);
  alloced += sz;
  gc_alloc += sz;
  // printf("Memcpy %li bytes to %p\n", sz, res);
  memcpy(res, obj, sz);
  set_forward(obj, res);
  return res;
}

static long** visit_lst = NULL;
static void visit(long *field);
static void visit_cb(long *field, void* ctx) {
  arrput(visit_lst, field);
}
static void visit(long *field) {
  arrput(visit_lst, field);
  while(arrlen(visit_lst)) {
    field = arrpop(visit_lst);
    auto from = *field;
    auto tag = from & TAG_MASK;
    //printf("TAG %li\n", tag);
    if (tag == PTR_TAG || tag == FLONUM_TAG || tag == CONS_TAG ||
	tag == CLOSURE_TAG || tag == SYMBOL_TAG) {
      auto p = from & (~TAG_MASK);
      //printf("Visiting ptr field %lx\n", p);
      auto to = is_forwarded(p) ? get_forward(p) : p;
      if (((uint32_t*)to)[1] == 0) {
	assert(to >= (long)alloc_start && to < (long)alloc_end);
	// If RC is 0.
	to = (long)copy((long*)p);
	((uint32_t*)to)[1]++;
	//printf("INC %p to %i (0)\n", to, ((uint32_t*)to)[1]);
	// Need to recursively visit all fields
	trace_heap_object((void*)to, visit_cb, NULL);
      } else {
	((uint32_t*)to)[1]++;
	//printf("INC %p to %i\n", to, ((uint32_t*)to)[1]);
	assert(to < (long)alloc_start || to >= (long)alloc_end);
      }
      //     printf("Visiting ptr field %lx moved to %lx \n", p, to);
      *field = to + tag;
    }
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
      arrput(next_decrements, t->consts[i]);
    }
  }
  for (uint64_t i = 0; i < arrlen(t->relocs); i++) {
    auto reloc = &t->relocs[i];
    auto old = reloc->obj;
    visit(&reloc->obj);
    arrput(next_decrements, reloc->obj);
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
  //printf("Scan symbols from readbc...%li\n", arrlen(symbols));
  for (uint64_t i = 0; i < arrlen(symbols); i++) {
    visit(&symbols[i]);
    //printf("Add readbc %p\n", symbols[i]);
    arrput(next_decrements, symbols[i]);
  }

  //printf("Scan GC pushed roots...%li\n", arrlen(pushed_roots));
  for (uint64_t i = 0; i < arrlen(pushed_roots); i++) {
    visit(pushed_roots[i]);
    //printf("Add GC root %p\n", *pushed_roots[i]);
    arrput(next_decrements, *pushed_roots[i]);
  }

  //printf("Scan stack...%u\n", stack_top - stack);
  for (long* sp = stack; sp <= stack_top; sp++) {
    if (*sp != 0) {
      visit(sp);
      //printf("Add stack root %p\n", *sp);
      arrput(next_decrements, *sp);
    }
  }

  /* This is required because the stack isn't fully acurate: 
   * CALL leaves a hole for the return address, and top-of-stack tracking
   * may be off by one, and not all instructions have top of stack tracking.
   *
   * The issue is if we only GC to the top of the stack, and junk left on the stack
   * may end up in a hole or used accidentally in top of stack off-by-one.
   * Just zero it out instead of implementing perfect tracking, or GC frame emission
   * in the compiler or something more complicated.
   * If the remaining stack is huge here, we may want to shrink it anyway?
   */
  memset(stack_top+1, 0, ((char*)frame_top - (char*)(stack_top+1)));
  //printf("Scan constant table... %li\n", const_table_sz);
  for (size_t i = 0; i < const_table_sz; i++) {
    if (const_table[i] != 0) {
      visit(&const_table[i]);
      //printf("Add const table %p\n", const_table[i]);
      arrput(next_decrements, const_table[i]);
    }
  }
  //printf("Scan symbol table...\n");
  for (size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[i];
    if (*cur != 0 && *cur != TOMBSTONE) {
      auto *tmp = (long *)&sym_table->entries[i];
      visit(tmp);
      //printf("Add symbol table %p\n", *tmp);
      arrput(next_decrements, *tmp);
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

extern size_t page_cnt;
size_t alloc_sz;

static void GC_deinit() {
  arrfree(pushed_roots);
  munmap(alloc_start, alloc_sz);
}

EXPORT void GC_init() {
  alloc_sz = 4096 * page_cnt;
  alloc_start = (uint8_t *)mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(alloc_start);
  alloc_ptr = alloc_start;
  alloc_end = alloc_ptr + alloc_sz;
  atexit(&GC_deinit);
}


static void trace2_cb(long* obj, void* ctx) {
  long **lst = (long**)ctx;
  arrput(*lst, *obj);
}
static int64_t trace2(long** lst, bool incr) {
  int64_t gc_freed = 0;
  while(arrlen(*lst)) {
    auto item = arrpop(*lst);
    auto ptr = item &~TAG_MASK;
    if (!is_ptr_type(item)) {
      continue;
    }
    assert(ptr < (long)alloc_start || ptr >= (long)alloc_end);
    if (((uint32_t*)ptr)[1] == 0) {
      printf("Found invalid RC count:  %lx \n", ptr);
      exit(-1);
    }
    assert(((uint32_t*)ptr)[1] != 0);
    if (incr) {
      ((uint32_t*)ptr)[1] ++;
      //printf("INC %p to %i\n", ptr, ((uint32_t*)ptr)[1]);
    } else {
      //printf("DEC %p to %i\n", ptr, ((uint32_t*)ptr)[1]);
      if(--((uint32_t*)ptr)[1] == 0) {
	// Recursive decrement
	auto sz =heap_object_size((long*)ptr);
	gc_alloc -= sz;
	gc_freed += sz;
	trace_heap_object((void*)ptr, trace2_cb, lst);
	free((void*)ptr);
      }
    }
  }
  return gc_freed;
}

#ifdef PROFILER
bool in_gc = false;
#endif
void GC_collect() {
  alloced = 0;
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
  //printf("Trace roots...\n");
  trace_roots();
  
  // Scan log buf, adding to cur_increments
  //  printf("Scan log buf...\n");
  scan_log_buf();
  // Run increments
  //printf("Run increments...\n");
  trace2(&cur_increments, true);
  arrsetlen(cur_increments, 0);
  // Run *last* iteration's decrements.
  //printf("Run %li decrements...\n", arrlen(cur_decrements));
  auto freed = trace2(&cur_decrements, false);
  arrsetlen(cur_decrements, 0);
  //printf("Done\n");
  
  if (verbose) {
    printf("Log buf size: %li\n", arrlen(log_buf));
  }
  /* alloced += alloc_sz; */
  /* freed += alloc_sz; */
  printf("Heap sz: %li alloced: %li freed: %li ratio: %.02f\n", gc_alloc, alloced, freed, ((double)freed / (double)alloced) * 100.0);
  arrsetlen(log_buf, 0);

  if ((alloced-freed) > (long)(alloc_sz/2)) {
    printf("SHOULD INCREASE HEAP---------------------\n");
  }

#ifdef PROFILER
  in_gc = false;
#endif
}

__attribute__((noinline)) void *GC_malloc_slow(size_t sz) {
  if (align(sz) >= alloc_sz) {
    printf("Alloc too big: %li\n", sz);
    abort();
  }
  GC_collect();
  alloc_ptr = alloc_start;
  return GC_malloc(sz);
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

static void scan_log_buf() {
  for(uint64_t i = 0; i < arrlen(log_buf); ) {
    auto cur = log_buf[i];
    assert(cur.offset == 0xffffffffffffffff);
    auto addr = cur.addr;
    uint32_t* rc_ptr = (uint32_t*)addr;
    rc_ptr[1] &= ~LOGGED_MARK;
    
    i++;
    cur = log_buf[i];
    while(cur.offset != 0xffffffffffffffff) {

      long*field = (long*)(addr + cur.offset);
      auto v = *field;
      auto type = v & TAG_MASK;
      if (type == PTR_TAG || type == FLONUM_TAG || type == CONS_TAG ||
	  type == CLOSURE_TAG || type == SYMBOL_TAG) {
	visit(field);
	//printf("Add log increments: %p\n", *field);
	//arrput(cur_increments, *field);
      }
      v = cur.addr;
      type = v & TAG_MASK;
      if (type == PTR_TAG || type == FLONUM_TAG || type == CONS_TAG ||
	  type == CLOSURE_TAG || type == SYMBOL_TAG) {
	//printf("Add log decrements: %p\n", v);
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

static void maybe_log(long* v_p, void* c) {
  long v = *v_p;
  uint64_t addr = (uint64_t)c;
  // TODO only maybe log if a ptr
  arrput(log_buf, ((log_item){(uint64_t)v_p - addr, v}));
}

static __attribute__((noinline)) void GC_log_obj_slow(void*obj) {
  uint32_t* rc_ptr = (uint32_t*)obj;
  rc_ptr[1] |= LOGGED_MARK;
  uint64_t addr = (uint64_t)obj;
  arrput(log_buf, ((log_item){0xffffffffffffffff, addr}));
  
  trace_heap_object(obj, maybe_log, (void*)addr);
}

void __attribute__((always_inline)) GC_log_obj(void*ptr) {
  uint32_t rc = ((uint32_t*)ptr)[1];
  if (unlikely((rc != 0) && (!(rc & LOGGED_MARK)))) {
    __attribute((musttail)) return GC_log_obj_slow(ptr);
  }
}
