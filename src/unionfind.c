#include <assert.h>
#include <smmintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "unionfind.h"

#include "third-party/stb_ds.h"

#define unlikely(x) __builtin_expect(!!(x), 0)

// Custom hashtable.  I tried to use stb_ds, but it was too slow:
// insertion/hashing isn't as fast as crc32+linear probe.
static uf_item *map_find(uf *ht, int64_t key) {
  int64_t start = _mm_crc32_u64(0, key);

  long sz_mask = ht->map_sz - 1;
  for (uint64_t i = 0; i < ht->map_sz; i++) {
    uint64_t slot = (i + start) & sz_mask;
    if (ht->map[slot].key == key) {
      return &ht->map[slot];
    }
    if (ht->map[slot].key == 0) {
      return NULL;
    }
  }
  return NULL;
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

  int64_t start = _mm_crc32_u64(0, key);
  long sz_mask = ht->map_sz - 1;
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
  ht->map = NULL;
  ht->map_cnt = 0;
  ht->map_sz = 0;
  ht->table = NULL;
}

void uf_free(uf *ht) {
  arrfree(ht->table);
  free(ht->map);
}

static uint64_t find(box *b, uint64_t idx) {
  while (idx != b[idx].parent) {
    b[idx].parent = b[b[idx].parent].parent;
    idx = b[idx].parent;
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

  if (!bx) {
    if (!by) {
      uint64_t bi = arrlen(ht->table);
      box b = {bi, 1};
      arrput(ht->table, b);
      map_insert(ht, y, bi);
      map_insert(ht, x, bi);
    } else {
      uint64_t ry = find(ht->table, by->value);
      map_insert(ht, x, ry);
    }
  } else {
    if (!by) {
      uint64_t rx = find(ht->table, bx->value);
      map_insert(ht, y, rx);
    } else {
      uint64_t rx = find(ht->table, bx->value);
      uint64_t ry = find(ht->table, by->value);
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
    }
  }
  return false;
}

/*
int main() {
  uf ht;
  uf_init(&ht);
  int64_t res = unionfind(&ht, 0, 1);
  res = unionfind(&ht, 1, 2);
  res = unionfind(&ht, 2, 4);
  res = unionfind(&ht, 3, 4);
  res = unionfind(&ht, 3, 0);
  if (!res) {
    printf("false\n");
  } else {
    printf("true\n");
  }
  uf_free(&ht);
  return 0;
}
*/
