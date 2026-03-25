// Equality checking based on
// "Efficient Nondestructive Equality Checking for Trees and Graphs"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hawk.h"
#include "runtime.h"
#include "types.h"
#include "util/array.h"
#include "util/util.h"

static inline gc_obj SCM_STRING_CMP(gc_obj a, gc_obj b) {
  auto sa = to_string(a);
  auto sb = to_string(b);
  int64_t len_a = to_fixnum(sa->len);
  int64_t len_b = to_fixnum(sb->len);
  if (len_a != len_b) {
    return tag_fixnum(len_a < len_b ? -1 : 1);
  }
  return tag_fixnum(strncmp(sa->str, sb->str, (size_t)len_a));
}

typedef struct {
  int64_t key;
  uint64_t value;
} uf_item;

typedef struct {
  uint64_t parent;
  uint64_t sz;
} box;

typedef box *box_vec;

typedef struct uf_s {
  // Map values contain indexes into table.
  uf_item *map;
  uint64_t map_cnt;
  uint64_t map_sz;
  // Table parent is index to table.
  // If it == self, it has no parent.
  box_vec table;
} uf;

void uf_init(uf *ht);
void uf_free(uf *ht);
bool unionfind(uf *ht, int64_t x, int64_t y);

// Custom hashtable.  I tried to use stb_ds, but it was too slow:
// insertion/hashing isn't as fast as crc32+linear probe.
static uf_item *map_find(uf *ht, int64_t key) {
  auto start = hashmix(key);

  auto sz_mask = ht->map_sz - 1;
  for (uint64_t i = 0; i < ht->map_sz; i++) {
    uint64_t slot = (i + start) & sz_mask;
    if (ht->map[slot].key == key) {
      return &ht->map[slot];
    }
    if (ht->map[slot].key == 0) {
      return nullptr;
    }
  }
  return nullptr;
}

static void map_insert(uf *ht, int64_t key, uint64_t value) {
  assert(key != 0);
  ht->map_cnt++;
  if (unlikely(ht->map_cnt >= ht->map_sz * 7 / 10)) {
    if (ht->map_sz == 0) {
      // We're already through 4k elements in equal?,
      // So start with a reasonably large map.
      ht->map_sz = 4096;
    }
    ht->map_sz *= 4;
    uf_item *old = ht->map;
    ht->map = malloc(sizeof(uf_item) * ht->map_sz);
    memset(ht->map, 0, sizeof(uf_item) * ht->map_sz);
    if (old) {
      for (uint64_t i = 0; i < ht->map_sz / 4; i++) {
        if (old[i].key) {
          map_insert(ht, old[i].key, old[i].value);
        }
      }
      free(old);
    }
  }

  auto start = hashmix(key);
  auto sz_mask = ht->map_sz - 1;
  for (uint64_t i = 0; i < ht->map_sz; i++) {
    uint64_t slot = (i + start) & sz_mask;
    if (ht->map[slot].key == 0) {
      ht->map[slot].key = key;
      ht->map[slot].value = value;
      return;
    }
  }
}

// A custom union-find algorithm for detecting cycles in equal?
void uf_init(uf *ht) {
  ht->map = nullptr;
  ht->map_cnt = 0;
  ht->map_sz = 0;
  ht->table = nullptr;
}

void uf_free(uf *ht) {
  arrfree(ht->table);
  free(ht->map);
}

static uint64_t find(box_vec *b, uint64_t i) {
  auto idx = i;
  while (idx != (*b)[idx].parent) {
    (*b)[idx].parent = (*b)[(*b)[idx].parent].parent;
    idx = (*b)[idx].parent;
  }
  return idx;
}

// Returns true iff they were both previously added,
// and are part of the same class.
//
// So returns false if x == y, and this is the first time
// we have seen them.
bool unionfind(uf *ht, int64_t x, int64_t y) {
  uf_item *bx = map_find(ht, x);
  uf_item *by = map_find(ht, y);

  if (bx) {
    if (by) {
      uint64_t rx = find(&ht->table, bx->value);
      uint64_t ry = find(&ht->table, by->value);
      if (rx == ry) {
        return true;
      }
      box *vx = &ht->table[rx];
      box *vy = &ht->table[ry];

      if (vx->sz > vy->sz) {
        vy->parent = rx;
        vx->sz++;
      } else {
        vx->parent = ry;
        vy->sz++;
      }
    } else {
      uint64_t rx = find(&ht->table, bx->value);
      map_insert(ht, y, rx);
    }
  } else {
    if (by) {
      uint64_t ry = find(&ht->table, by->value);
      map_insert(ht, x, ry);
    } else {
      uint64_t bi = arrlen(ht->table);
      box b = {bi, 1};
      arrput(ht->table, b);
      map_insert(ht, y, bi);
      map_insert(ht, x, bi);
    }
  }
  return false;
}
/*
#include <stdio.h>
int main() {
  uf ht;
  uf_init(&ht);
  int64_t res = unionfind(&ht, 1, 1);
  // res = unionfind(&ht, 2, 2);
  res = unionfind(&ht, 3, 4);
  res = unionfind(&ht, 1, 3);
  res = unionfind(&ht, 4, 1);
  if (!res) {
    printf("false\n");
  } else {
    printf("true\n");
  }
  uf_free(&ht);
  return 0;
}
*/

static const int64_t kb = -20;
static const int64_t k0 = 200;
typedef struct {
  bool v;
  int64_t k;
} ep_result;
static ep_result ep(uf *ht, bool unused, gc_obj a, gc_obj b, int64_t k);
static ep_result equalp_interleave(uf *ht, bool fast, gc_obj a, gc_obj b,
                                   int64_t k) {
  // eq?
  if (a.value == b.value) {
    return (ep_result){true, k};
  }

  // Check cons, vector, string for equalp?
  // cons and vector check unionfind table for cycles.
  if (is_cons(a)) {
    if (is_cons(b)) {
      auto cell_a = to_cons(a);
      auto cell_b = to_cons(b);
      if (!fast && unionfind(ht, a.value, b.value)) {
        return (ep_result){true, 0};
      }
      // Decrement k once
      auto res = ep(ht, fast, cell_a->a, cell_b->a, k - 1);
      if (!res.v) {
        return res;
      }
      // And pass k through.
      [[clang::musttail]] return ep(ht, fast, cell_a->b, cell_b->b, res.k);
    }
    return (ep_result){false, k};
  }
  if (is_vector(a) && is_vector(b)) {
    auto va = to_vector(a);
    auto vb = to_vector(b);
    if (va->len.value != vb->len.value) {
      return (ep_result){false, k};
    }
    if (!fast && unionfind(ht, a.value, b.value)) {
      return (ep_result){true, 0};
    }
    // Decrement K once for the vector, but return same K value
    uint64_t lim = to_fixnum(va->len);
    for (uint64_t i = 0; i < lim; i++) {
      auto res = ep(ht, fast, va->v[i], vb->v[i], k - 1);
      if (!res.v) {
        return res;
      }
    }
    return (ep_result){true, k};
  }
  // string=?
  if (is_string(a)) {
    if (is_string(b)) {
      if (SCM_STRING_CMP(a, b).value == 0) {
        return (ep_result){true, k};
      }
    }
    return (ep_result){false, k};
  }
  // bytevector=?
  /* if (is_bytevector(a)) { */
  /*   if (is_bytevector(b)) { */
  /*     auto bva = to_bytevector(a); */
  /*     auto bvb = to_bytevector(b); */
  /*     if (bva->len.value != bvb->len.value) { */
  /*       return (ep_result){false, k}; */
  /*     } */
  /*     if (memcmp(bva->v, bvb->v, to_fixnum(bva->len)) == 0) { */
  /*       return (ep_result){true, k}; */
  /*     } */
  /*   } */
  /*   return (ep_result){false, k}; */
  /* } */
  // eqvp?
  if (obj_jeqv(a, b)) {
    return (ep_result){true, k};
  }
  return (ep_result){false, k};
}

static ep_result ep(uf *ht, bool unused, gc_obj a, gc_obj b, int64_t k) {
  if (k <= 0) {
    if (k == kb) {
      MUSTTAIL return equalp_interleave(ht, true, a, b, k0 * 2);
    } else {
      MUSTTAIL return equalp_interleave(ht, false, a, b, k);
    }
  } else {
    MUSTTAIL return equalp_interleave(ht, true, a, b, k);
  }
}

EXPORT gc_obj SCM_EQUAL(gc_obj a, gc_obj b) {
  uf ht;
  uf_init(&ht);
  int64_t k = k0;

  ep_result res = ep(&ht, true, a, b, k);

  uf_free(&ht);
  if (res.v) {
    return TRUE_REP;
  }
  return FALSE_REP;
}
