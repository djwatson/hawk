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

/*
An RC-immix style GC.  Like many other immix variants though, we munge blocks& lines a bit.

boom's VM: exact, we always know on the stack what is a pointer and what isn't.  However, 
           we may point to stale data, so we need to clear any 'unused' stack portions each GC.

Notes:
  I tried not-copying at all for nursury, and it seemed to be *worse* due to locality issues, even if
  GC stops were shorter.

  Full GC's almost never happen assuming small enough blocks (~256k), fragmentation never really exceeds 20%.
  Additionally, there are almost no cycles generated, except for very small heaps (<50mb).

  However, having small blocks, while not collecting until X bytes
  later, is *very* important.  Currently root scanning is expensive
  for large numbers of traces, and also the less we scan, the less we
  have to copy and RC.

  Currently, 256kB 'blocks' and 64MB collect frequency seems to be best.
 */

#define auto __auto_type
#define unlikely(x) __builtin_expect(!!(x), 0)

extern bool verbose;

extern long *stack;
extern long* stack_top;
extern long* frame_top;

static bool gc_enable = true;
static long gc_alloc = 0;
static long gc_dalloc = 0;
static long gc_large = 0;

uint8_t *alloc_start = NULL;
uint8_t *alloc_ptr = NULL;
uint8_t *alloc_end = NULL;

void** large_allocs = NULL;

long **pushed_roots = NULL;

static const uint32_t LOGGED_MARK = (1UL << 31);

typedef struct {
  uint64_t offset;
  uint64_t addr;
} log_item;

#define COLLECT_CNT_LOG 26
#define ALLOC_SZ_LOG 18
#define ALLOC_SZ (1UL << ALLOC_SZ_LOG)
#define ALLOC_SZ_MASK (ALLOC_SZ-1)

size_t align(size_t sz) { return (sz + 7) & (~TAG_MASK); }
typedef struct {
  uint64_t cnt;
  uint8_t marks[((ALLOC_SZ / 64)+8)&~8];
  uint8_t data[];
} gc_block;
gc_block* cur_block = NULL;

static void block_bts(gc_block* block, uint64_t loc) {
  uint64_t bit = (loc - (uint64_t)block->data)/8;
  auto word = bit/8;
  auto b = bit % 8;
  assert(word < (((ALLOC_SZ / 64)+8)&~8));
  block->marks[word]|= 1UL << b;
}
static bool block_bt(gc_block* block, uint64_t loc) {
  uint64_t bit = (loc - (uint64_t)block->data)/8;
  auto word = bit/8;
  auto b = bit % 8;
  assert(word < (((ALLOC_SZ / 64)+8)&~8));
  return block->marks[word]& (1UL << b);
}

static gc_block** gc_blocks = NULL;
static gc_block** free_gc_blocks = NULL;

static log_item* log_buf = NULL;
static long** cur_increments = NULL;
static long* next_decrements = NULL;
static long* cur_decrements = NULL;

static void scan_log_buf(void(*add_increment)(long*));

static gc_block* alloc_gc_block() {
  gc_alloc += ALLOC_SZ;
  if (arrlen(free_gc_blocks)) {
    return arrpop(free_gc_blocks);
  }
  void* res;
  if(posix_memalign(&res, ALLOC_SZ, ALLOC_SZ)) {
    printf("posix_memalign error\n");
    exit(-1);
  }
  gc_block* mem = (gc_block*)res;
  arrput(gc_blocks, mem);
  mem->cnt = 0;
  return mem;
}

static void put_gc_block(gc_block * mem) {
  gc_alloc -= ALLOC_SZ;
  assert(mem->cnt == 0);
  arrput(free_gc_blocks, mem);
}

bool is_ptr_type(long obj) {
  auto type = obj & TAG_MASK;
  if (type == PTR_TAG || type == FLONUM_TAG || type == CONS_TAG ||
      type == CLOSURE_TAG || type == SYMBOL_TAG) {
    return true;
  }
  return false;
}

bool is_gc_ptr(long obj) {
  if (!is_ptr_type(obj)) {
    return true;
  }
  for(uint64_t i = 0; i < arrlen(gc_blocks);i++) {
    auto block = gc_blocks[i];
    if (obj >= (long)block && obj <= (long)block + ALLOC_SZ) {
      return true;
    }
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


static gc_block* cur_copy_block = NULL;
static uint8_t* copy_alloc_ptr = NULL;
static uint8_t* copy_alloc_end = NULL;
void *copy(long *obj) {
  //printf("COPY obj %p, type %li\n", obj, *obj);
  size_t sz = align(heap_object_size(obj));
  gc_block* block = (gc_block*)((long)obj & ~ALLOC_SZ_MASK);
  if ((long)block == (long)obj) {
    return obj;
  }
  if (copy_alloc_ptr + sz >= copy_alloc_end) {
    assert(cur_copy_block == NULL || cur_copy_block->cnt != 0);
    if(cur_copy_block) {
      // Prevent from being collected prematurely.
      cur_copy_block->cnt--;
    }
    cur_copy_block = alloc_gc_block();
    copy_alloc_ptr = (uint8_t*)&cur_copy_block->data[0];
    copy_alloc_end = copy_alloc_ptr + ALLOC_SZ - sizeof(gc_block);
    assert(copy_alloc_ptr + sz < copy_alloc_end);
    cur_copy_block->cnt++;
  }
  auto *res = copy_alloc_ptr;
  gc_dalloc += sz;
  copy_alloc_ptr += sz;
  cur_copy_block->cnt++;
  //printf("Memcpy %li bytes to %p\n", sz, res);
  memcpy(res, obj, sz);
  set_forward(obj, res);
  return res;
}

static void visit_cb(long *field, void* ctx) {
  long ***lst = (long***)ctx;
  if (is_ptr_type(*field)) {
    arrput(*lst, field);
  }
}
static bool fully_trace = false;
static void clear_block_marks() {
  for(uint64_t i = 0; i < arrlen(gc_blocks); i++) {
    auto block = gc_blocks[i];
    block->cnt =0;
    if (cur_copy_block == block) {
      block->cnt++;
    }
    memset(block->marks, 0, sizeof(block->marks));
  }
  gc_dalloc = 0;
}
static void full_trace(long *field) {
  long*** lst = &cur_increments;
  while(true) {
    auto from = *field;
    auto tag = from & TAG_MASK;
    if (!is_ptr_type(from)) {
      goto next;
    }
    auto p = from & (~TAG_MASK);
      auto to = is_forwarded(p) ? get_forward(p) : p;
      //printf("TAG %li\n", tag);
      //printf("Visiting ptr field %lx\n", p);
      gc_block* block = (gc_block*)(to & ~ALLOC_SZ_MASK);
      if (to == (long)block) {
	gc_dalloc += heap_object_size((long*)to);
	goto next;
      }
      if (!block_bt(block, to)) {
	//assert(to >= (long)alloc_start && to < (long)alloc_end);
	// If RC is 0.
	to = (long)copy((long*)p);
	block = (gc_block*)(to & ~ALLOC_SZ_MASK);
	block_bts(block, to );
	((uint32_t*)to)[1] = 1;
	//printf("INC %p to %i (0)\n", to, ((uint32_t*)to)[1]);
	// Need to recursively visit all fields
	trace_heap_object((void*)to, visit_cb, lst);
      } else {
	((uint32_t*)to)[1]++;
	//printf("INC %p to %i\n", to, ((uint32_t*)to)[1]);
	//assert(to < (long)alloc_start || to >= (long)alloc_end);
      }
      //     printf("Visiting ptr field %lx moved to %lx \n", p, to);
      *field = to + tag;
  next:
    if (arrlen(cur_increments) == 0) {
      break;
    }
    field = arrpop(cur_increments);
  }
}
__attribute__((noinline)) static void sweep_free_blocks() {
  gc_alloc = 0;
  arrsetlen(free_gc_blocks, 0);
  for(uint64_t i = 0; i < arrlen(gc_blocks); i++) {
    auto block = gc_blocks[i];
    if (block->cnt == 0) {
      put_gc_block(block);
    }
    gc_alloc += ALLOC_SZ;
  }
}
static void visit(long *field) {
  long***lst = &cur_increments;
  while(true) {
    auto from = *field;
    auto tag = from & TAG_MASK;
    if (!is_ptr_type(from)) {
      goto next;
    }
    auto p = from & (~TAG_MASK);
      auto to = is_forwarded(p) ? get_forward(p) : p;
      //printf("TAG %li\n", tag);
      //printf("Visiting ptr field %lx\n", p);
      if (((uint32_t*)to)[1] == 0) {
	//assert(to >= (long)alloc_start && to < (long)alloc_end);
	// If RC is 0.
	to = (long)copy((long*)p);
	((uint32_t*)to)[1]++;
	//printf("INC %p to %i (0)\n", to, ((uint32_t*)to)[1]);
	// Need to recursively visit all fields
	trace_heap_object((void*)to, visit_cb, lst);
      } else {
	((uint32_t*)to)[1]++;
	//printf("INC %p to %i\n", to, ((uint32_t*)to)[1]);
	//assert(to < (long)alloc_start || to >= (long)alloc_end);
      }
      //     printf("Visiting ptr field %lx moved to %lx \n", p, to);
      *field = to + tag;
  next:
    if (arrlen(cur_increments) == 0) {
      break;
    }
    field = arrpop(cur_increments);
  }
}

// Static roots are the stack - stacksz,
// the symbol table,
// and the constant table.
// and symbols?????? shit
extern trace_s *trace;
extern trace_s **traces;
extern long *symbols;

static void visit_trace(trace_s *t, void(*add_root)(long*root)) {
  for (size_t i = 0; i < arrlen(t->consts); i++) {
    if (t->consts[i]) {
      add_root(&t->consts[i]);
    }
  }
  for (uint64_t i = 0; i < arrlen(t->relocs); i++) {
    auto reloc = &t->relocs[i];
    auto old = reloc->obj;
    add_root(&reloc->obj);
    if (reloc->obj != old) {
      switch (reloc->type) {
      case RELOC_ABS: {
	int64_t v = reloc->obj;
	memcpy((int64_t*)(reloc->offset - 8), &v, sizeof(int64_t));
        break;
      }
      case RELOC_ABS_NO_TAG: {
	int64_t v = reloc->obj;
	v &= ~TAG_MASK;
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
static void trace_roots(void(*add_root)(long*root)) {
  //printf("Scan symbols from readbc...%li\n", arrlen(symbols));
  for (uint64_t i = 0; i < arrlen(symbols); i++) {
    add_root(&symbols[i]);
  }

  //printf("Scan GC pushed roots...%li\n", arrlen(pushed_roots));
  for (uint64_t i = 0; i < arrlen(pushed_roots); i++) {
    add_root(pushed_roots[i]);
  }

  //printf("Scan stack...%u\n", stack_top - stack);
  for (long* sp = stack; sp <= stack_top; sp++) {
    if (*sp != 0) {
      add_root(sp);
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
      add_root(&const_table[i]);
    }
  }
  //printf("Scan symbol table...\n");
  for (size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[i];
    if (*cur != 0 && *cur != TOMBSTONE) {
      auto *tmp = (long *)&sym_table->entries[i];
      add_root(tmp);
    }
  }

// Scan traces
#ifdef JIT
  for (uint64_t i = 0; i < arrlen(traces); i++) {
    auto *t = traces[i];
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

static struct  {
  uint64_t traces;
  uint64_t full_traces;
} gc_stats = {0,0};
static void GC_deinit() {
  /* arrfree(pushed_roots); */
  /* munmap(alloc_start, alloc_sz); */
  printf("Traces %li Full traces %li (%.02f)\n",
	 gc_stats.traces,
	 gc_stats.full_traces,
	 ((double)gc_stats.full_traces / (double)gc_stats.traces)*100.0
	 );
}

EXPORT void GC_init() {
  /* alloc_start = (uint8_t *)mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE, */
  /*                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); */
  /* assert(alloc_start); */
  /* alloc_ptr = alloc_start; */
  /* alloc_end = alloc_ptr + alloc_sz; */
  atexit(&GC_deinit);
  cur_block = alloc_gc_block();
  alloc_start = (uint8_t*)&cur_block->data[0];
  alloc_ptr = alloc_start;
  alloc_end = alloc_start + ALLOC_SZ - sizeof(gc_block);
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
    if (incr) {
      if (((uint32_t*)ptr)[1] == 0) {
	// Increment line in block
	gc_block* block = (gc_block*)(item & ~ALLOC_SZ_MASK);
	if ((long)block != ptr) {
	  block->cnt++;
	  gc_dalloc += heap_object_size((long*)ptr);
	}
	trace_heap_object((void*)ptr, trace2_cb, lst);
      }
      ((uint32_t*)ptr)[1] ++;
      //printf("INC %p to %i\n", ptr, ((uint32_t*)ptr)[1]);
    } else {
      //printf("DEC %p to %i\n", ptr, ((uint32_t*)ptr)[1]);
      if(--((uint32_t*)ptr)[1] == 0) {
	// Recursive decrement
	auto sz =heap_object_size((long*)ptr);
	trace_heap_object((void*)ptr, trace2_cb, lst);
	gc_block* block = (gc_block*)(item & ~ALLOC_SZ_MASK);
	if ((long)block == ptr) {
	  //printf("Free %p\n", ptr);
	  free(block);
	  // unlink
	  for(uint32_t i = 0; i < arrlen(large_allocs); i++) {
	    if ((long)large_allocs[i] == ptr) {
	      large_allocs[i] = NULL;
	      break;
	    }
	  }
	}else {
	  gc_dalloc -= sz;
	  if (--block->cnt == 0) {
	    put_gc_block(block);
	  }
	}
      }
    }
  }
  return gc_freed;
}

static __attribute__((always_inline))void add_root(long* root) {
    full_trace(root);
    // Must reload root in case it was forwarded.
    arrput(next_decrements, *root);
}

static __attribute__((always_inline))void add_root2(long* root) {
    visit(root);
    arrput(next_decrements, *root);
}

__attribute__((always_inline))void add_increment2(long* root) {
  long obj = *root;
  if (is_ptr_type(obj)) {
    visit(root);
  }
}

#ifdef PROFILER
bool in_gc = false;
#endif
__attribute__((noinline)) void GC_collect() {
  cur_block = NULL;
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
  
  // Scan log buf, adding to cur_increments
  //  printf("Scan log buf...\n");
  // Run increments
  //printf("Run increments...\n");
  cur_block = NULL;
  gc_stats.traces++;
  if (fully_trace) {
    clear_block_marks();
    trace_roots(&add_root);
    //scan_log_buf(&add_increment);
    // TODO large object space?
    arrsetlen(log_buf, 0);
    //sweep_free_blocks();
    gc_stats.full_traces++;
  } else {
    trace_roots(&add_root2);
    scan_log_buf(&add_increment2);
  }
  arrsetlen(cur_increments, 0);
  // Run *last* iteration's decrements.
  //printf("Run %li decrements...\n", arrlen(cur_decrements));
  if (!fully_trace) {
    trace2(&cur_decrements, false);
  }
  arrsetlen(cur_decrements, 0);
  //printf("Done\n");

  for(uint32_t i =0; i < arrlen(large_allocs); i++) {
    if (large_allocs[i] && ((uint32_t*)large_allocs[i])[1] == 0) {
      free(large_allocs[i]);
    }
  }
  arrsetlen(large_allocs, 0);
  sweep_free_blocks();
  double ratio = ((double)gc_dalloc / (double)gc_alloc) * 100.0;
  if (verbose) {
    printf("Heap sz: %li alloced: %li ratio: %.02f full: %i\n", gc_alloc, gc_dalloc, ratio, fully_trace);
  }
  arrsetlen(log_buf, 0);

  auto can_auto_adjust = (arrlen(gc_blocks) - arrlen(free_gc_blocks)) > 10;

  if (can_auto_adjust && ratio < 90.0) {
    fully_trace = true;
  } else {
    fully_trace = false;
  }


    cur_block = alloc_gc_block();


  alloc_start = (uint8_t*)&cur_block->data[0];
  alloc_ptr = alloc_start;
  alloc_end = alloc_start + ALLOC_SZ - sizeof(gc_block);
#ifdef PROFILER
  in_gc = false;
#endif
}

__attribute__((noinline)) void *GC_malloc_slow(size_t sz) {
  if (align(sz) >= (ALLOC_SZ - sizeof(gc_block))) {
    if (gc_large > (1 << COLLECT_CNT_LOG)) {
      GC_collect();
      //printf("Collect\n");
      gc_large = 0;
    }
    void* res;
    if(posix_memalign(&res, ALLOC_SZ, align(sz))) {
      abort();
    }
    arrput(large_allocs, res);
    //printf("Alloc %p\n", res);
    gc_large += align(sz);
    return res;
  }
  static long cnt = 0;
  if (++cnt * ALLOC_SZ < (1UL << COLLECT_CNT_LOG)) {
    cur_block = alloc_gc_block();
    alloc_start = (uint8_t*)&cur_block->data[0];
    alloc_ptr = alloc_start;
    alloc_end = alloc_start + ALLOC_SZ - sizeof(gc_block);
  }  else {
    cnt = 0;
    GC_collect();
  }
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

static void scan_log_buf(void(*add_increment)(long*)) {
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
	//printf("Add log increments: %p\n", *field);
	add_increment(field);
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

__attribute__((noinline)) void GC_log_obj_slow(void*obj) {
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

