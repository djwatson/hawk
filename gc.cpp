#include "gc.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/mman.h>

#include "types.h"
#include "bytecode.h"
#include "symbol_table.h"

extern long *stack;
extern unsigned int stacksz;

static bool gc_enable = true;

static uint8_t* alloc_ptr = nullptr;
static uint8_t* alloc_end = nullptr;

void GC_enable(bool en) {
  gc_enable = en;
}

static bool is_forwarded(long obj) {
  auto ptr = (long*)obj;
  if (((*ptr)&TAG_MASK) == FORWARD_TAG) {
    return true;
  }
  return false;
}

static void set_forward(long* ptr, void* to) {
  assert(((*ptr)&TAG_MASK) != FORWARD_TAG);
  *ptr = (long)to + FORWARD_TAG;
}

static long get_forward(long obj) {
  assert(is_forwarded(obj));
  auto ptr = (long*)obj;
  printf("Obj %p forwarded to %lx\n", ptr, (*ptr) - FORWARD_TAG);
  return (*ptr) - FORWARD_TAG;
}

size_t heap_object_size(long* obj) {
  auto type = *obj;
  assert((type*TAG_MASK) != FORWARD_TAG);
  switch(type) {
  case FLONUM_TAG:
    printf("flonum\n");
    return sizeof(flonum_s);
  case STRING_TAG: {
    printf("string\n");
    auto str = (vector_s*)obj;
    return str->len*sizeof(char) + 16;
  }
  case SYMBOL_TAG:
    printf("symbol\n");
    return sizeof(symbol);
  case VECTOR_TAG: {
    printf("vec\n");
    auto vec = (vector_s*)obj;
    return vec->len*sizeof(long) + 16;
  }
  case CONS_TAG:
    printf("cons\n");
    return sizeof(cons_s);
  case CLOSURE_TAG: {
    printf("closure\n");
    auto clo = (closure_s*)obj;
    return clo->len*sizeof(long) + 16;
  }
  case PORT_TAG:
    printf("port\n");
    return sizeof(port_s);
  default:
    printf("Unknown heap object: %li\n", type);
    assert(false);
  }
}

size_t align(size_t sz) {
  return (sz+7)&(~TAG_MASK);
}

void* copy(long* obj) {
  printf("COPY obj %p, type %li\n", obj, *obj);
  size_t sz = heap_object_size(obj);
  auto res = alloc_ptr;
  printf("Memcpy %li bytes to %p\n", sz, res);
  memcpy(res, obj, sz);
  set_forward(obj, res);
  alloc_ptr += align(sz);
  assert(alloc_ptr < alloc_end);
  return res;
}

void visit(long* field) {
  auto from = *field;
  auto tag = from&TAG_MASK;
  printf("TAG %li\n", tag);
  if (tag == PTR_TAG || tag == FLONUM_TAG || tag == CONS_TAG || tag == CLOSURE_TAG || tag == SYMBOL_TAG) {
    auto p = from&(~TAG_MASK);
    auto to = is_forwarded(p) ? get_forward(p) : (long)copy((long*)p);
    *field = to + tag;
  } 
}

void trace_heap_object(long* obj) {
  auto type = *obj;
  assert((type&TAG_MASK) != FORWARD_TAG);
  switch(type) {
  case FLONUM_TAG:
    break;
  case STRING_TAG: 
    break;
  case SYMBOL_TAG: {
    auto sym = (symbol*)obj;
    // temporarily add back the tag
    obj[1] = (long)sym->name + SYMBOL_TAG;
    visit(&obj[1]);
    obj[1] = (long)sym->name - SYMBOL_TAG;
    visit(&sym->val);
    break;
  }
  case VECTOR_TAG: {
    auto vec = (vector_s*)obj;
    for(long i = 0; i < vec->len; i++) {
      visit(&vec->v[i]);
    }
    break;
  }
  case CONS_TAG: {
    auto cons = (cons_s*)obj;
    visit(&cons->a);
    visit(&cons->b);
    break;
  }
  case CLOSURE_TAG: {
    auto clo = (closure_s*)obj;
    // Note start from 1: first field is bcfunc* pointer.
    for(long i = 1; i < clo->len; i++) {
      visit(&clo->v[i]);
    }
    break;
  }
  case PORT_TAG:
    break;
  default:
    printf("Unknown heap object: %li\n", type);
    exit(-1);
  }
}

// Static roots are the stack - stacksz,
// the symbol table,
// and the constant table.
//
// Currently functions aren't GC'd.
static void trace_roots() {
  printf("Scan stack...%u\n", stacksz);
  for(size_t i = 0; i < stacksz; i++)  {
    if (stack[i] != 0) {
      visit(&stack[i]);
    }
  }
  printf("Scan constant table... %li\n", const_table_sz);
  for(size_t i = 0; i < const_table_sz; i++)  {
    if (const_table[i] != 0) {
      visit(&const_table[i]);
    }
  }
  printf("Scan symbol table...\n");
  for(size_t i = 0; i < sym_table->sz; i++) {
    auto&cur = sym_table->entries[i];
    if (cur != nullptr && cur != TOMBSTONE) {
      auto tmp = (long*)&sym_table->entries[i];
      *tmp += SYMBOL_TAG;
      visit(tmp);
      *tmp -= SYMBOL_TAG;
    }
  }
}

static constexpr size_t page_cnt = 2;
static constexpr size_t alloc_sz = 4096*page_cnt;
uint8_t* prev_mmap = nullptr;
void* GC_malloc(size_t sz) {
  sz = (sz+7)&(~TAG_MASK);
  assert((sz&TAG_MASK) == 0);
  auto res = alloc_ptr;
  alloc_ptr += sz;
  if ((!gc_enable) && (alloc_ptr < alloc_end)) {
    return res;
  }

  // Slowpath.
  if (sz >= alloc_sz) {
    printf("LArge alloc: %li\n", sz);
    assert(false);
  }
  printf("Collecting...\n");
  assert(gc_enable || alloc_end == nullptr);
  // flip
  //alloc_ptr = (uint8_t*)malloc(alloc_sz);
  alloc_ptr = (uint8_t*)mmap(NULL, alloc_sz, PROT_READ|PROT_WRITE,
			     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  auto alloc_start = alloc_ptr;
  assert(alloc_ptr);
  alloc_end = alloc_ptr + alloc_sz;
  auto scan = alloc_ptr;
  trace_roots();
  printf("Cheney scan... %p %p\n", scan, alloc_ptr);
  while(scan < alloc_ptr) {
    auto scan_sz = heap_object_size((long*)scan);
    trace_heap_object((long*)scan);
    scan += align(scan_sz);
  }
  printf("...Done collect, in use %li\n", alloc_ptr - alloc_start);
  if (prev_mmap) {
    mprotect(prev_mmap, alloc_sz, PROT_NONE);
  }
  prev_mmap = alloc_start;
  
  res = alloc_ptr;
  alloc_ptr += sz;
  if (alloc_ptr >= alloc_end) {
    printf("Heap exhausted, embiggen?\n");
    assert(false);
  }
  return res;
}

void* GC_realloc(void* ptr, size_t sz) {
  // TODO zero-mem
  return realloc(ptr, sz);
}

void GC_free(void* ptr) {
  free(ptr);
}
