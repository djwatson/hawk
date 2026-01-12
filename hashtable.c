// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"
#include "zone_alloc.h"

/*
The main motivation for *yet another hash table* was getting one that
would pass all the linters in C without much complaint.

Secondary, it wouldn't explode compile times.

Also, it zone-allocates.

So overall we're left with few macros as possible in the header, just
enough to type-erase the key and value type, and most of the work in
the C file - this depends on LTO to get any sort of performance.

It's a node-allocating, linear probing hashmap, pretty
straightforward.  Since it's node allocating, iteration is fast.
Since it's linear probing, deletions (tombstones) tend to slow it down
quite a bit, but if there are few / no deletions, it's as fast as
anything else.

Occupancy is currently set at 50%.
 */

hash_header *hm_header(void const *t) { return (hash_header *)((char *)t) - 1; }

enum : uint32_t {
  HM_EMPTY = 0,
  HM_TOMBSTONE = UINT32_MAX,
};

size_t hm_len(void const *t) {
  if (t == nullptr) {
    return 0;
  }
  return hm_header(t)->length;
}

static size_t hash_key(void *key, size_t keysize, bool string) {
  size_t hash = 0xcbf29ce484222325;
  uint8_t const *bytes = (uint8_t *)key;

  if (string) {
    keysize = strlen(*(char **)key);
    bytes = *(uint8_t **)key;
  }

  for (size_t i = 0; i < keysize; ++i) {
    hash ^= bytes[i];
    hash *= 0x100000001b3;
  }
  return hash;
}

static bool cmp_key(void *key, void *key2, size_t keysize, bool string) {
  if (string) {
    return 0 == strcmp(*(char **)key, *(char **)key2);
  }
  return 0 == memcmp(key, key2, keysize);
}

ptrdiff_t hm_geti_internal(void const *t, size_t elemsize, void *key,
                           size_t keysize, bool string) {
  if (t == nullptr) {
    return -1;
  }
  auto header = hm_header(t);
  // Try to find it
  uint64_t sz = header->capacity * 2;
  uint64_t mask = sz - 1;
  auto hash = hash_key(key, keysize, string);
  for (size_t i = 0; i < sz; i++) {
    auto probe = (hash + i) & mask;
    uint32_t elem = header->table[probe];
    if (elem == HM_EMPTY) {
      // Key does not exist
      header->tmp = -1;
      return -1;
    }
    if (elem == HM_TOMBSTONE) {
      continue;
    }
    elem--; // We're indexed off by one, because 0 means dne.
    if (cmp_key((char *)t + (elem * elemsize), key, keysize, string)) {
      // Key exists, test
      header->tmp = elem;
      return elem;
    }
  }

  header->tmp = -1;
  return -1;
}

bool hm_del_internal(void const *t, size_t elemsize, void *key, size_t keysize,
                     bool string) {
  if (t == nullptr) {
    return false;
  }
  auto header = hm_header(t);
  // Try to find it
  uint64_t sz = header->capacity * 2;
  uint64_t mask = sz - 1;
  auto hash = hash_key(key, keysize, string);
  for (size_t i = 0; i < sz; i++) {
    auto probe = (hash + i) & mask;
    uint32_t elem = header->table[probe];
    if (elem == 0) {
      // Key does not exist
      return false;
    }
    if (elem == HM_TOMBSTONE) {
      continue;
    }
    elem--; // We're indexed off by one, because 0 means dne.
    if (!cmp_key((char *)t + (elem * elemsize), key, keysize, string)) {
      continue;
    }
    // Key exists, test
    header->table[probe] = HM_TOMBSTONE;
    header->length--;

    if (header->length == 0) {
      return false;
    }
    if (elem == header->length) {
      return false;
    }
    // Shuffle the last item in to the spot of the one we deleted
    memcpy((char *)t + (elem * elemsize),
           (char *)t + (header->length * elemsize), elemsize);
    hash = hash_key((char *)t + (header->length * elemsize), keysize, string);
    for (size_t j = 0; j < sz; j++) {
      auto probe2 = (hash + j) & mask;
      uint32_t elem2 = header->table[probe2];
      assert(elem2);
      if (elem2 == HM_TOMBSTONE) {
        continue;
      }
      elem2--; // We're indexed off by one, because 0 means dne.
      if (cmp_key((char *)t + (elem2 * elemsize), (char *)t + (elem * elemsize),
                  keysize, string)) {
        header->table[probe2] = elem + 1;
        return true;
      }
    }
    assert(false);
  }
  // All tombstones.
  return false;
}

static void *hm_expand(zone *z, void const *t, size_t elemsize, size_t keysize,
                       bool string) {
  hash_header const *header = nullptr;
  size_t new_size = 4;
  if (t) {
    header = hm_header(t);
    new_size = header->capacity * 2;
  }
  hash_header *new_header = zone_realloc(
      z, header, t ? sizeof(hash_header) + (elemsize * header->capacity) : 0,
      sizeof(hash_header) + (new_size * elemsize));
  new_header->table = zone_malloc(z, new_size * 2 * sizeof(uint32_t));
  new_header->capacity = new_size;
  void *new_t = (char *)new_header + sizeof(hash_header);

  if (header) {
    // Rehash
    uint64_t sz = new_header->capacity * 2;
    uint64_t mask = sz - 1;
    for (uint64_t i = 0; i < new_header->length; i++) {
      auto hash = hash_key((char *)new_t + (i * elemsize), keysize, string);
      for (uint64_t j = 0; j < sz; j++) {
        auto probe = (hash + j) & mask;
        auto elem = new_header->table[probe];
        if (!elem) {
          new_header->table[probe] = i + 1;
          break;
        }
      }
    }
  } else {
    new_header->length = 0;
  }
  return new_t;
}

void *hm_put_internal(zone *z, void *t, size_t elemsize, void *key,
                      size_t keysize, bool string) {
  if (!t) {
    t = hm_expand(z, t, elemsize, keysize, string);
  }
  auto header = hm_header(t);
  if (header->length == header->capacity) {
    t = hm_expand(z, t, elemsize, keysize, string);
    header = hm_header(t);
  }

  // Try to find it
  uint64_t sz = header->capacity * 2;
  uint64_t mask = sz - 1;
  auto hash = hash_key(key, keysize, string);
  for (size_t i = 0; i < sz; i++) {
    auto probe = (hash + i) & mask;
    uint32_t elem = header->table[probe];
    if (elem == 0 || elem == HM_TOMBSTONE) {
      // Key does not exist
      memcpy((char *)t + (elemsize * header->length), key, keysize);
      header->tmp = header->length;
      header->length++;
      header->table[probe] = header->length;
      return t;
    }
    elem--; // We're indexed off by one, because 0 means dne.
    if (cmp_key((char *)t + (elem * elemsize), key, keysize, string)) {
      // Key exists, test
      header->tmp = elem;
      return t;
    }
  }
  assert(false);
  return t;
}

/*
int main() {
  zone z = {0};
  struct {
    int key;
  } *set = nullptr;
  assert(hm_len(set) == 0);
  hm_insert(&z, set, 1);
  assert(hm_len(set) == 1);
  hm_insert(&z, set, 1);
  assert(hm_len(set) == 1);
  hm_insert(&z, set, 10);
  assert(hm_len(set) == 2);
  hm_insert(&z, set, 20);
  assert(hm_len(set) == 3);
  hm_insert(&z, set, 30);
  assert(hm_len(set) == 4);
  hm_insert(&z, set, 40);
  assert(hm_contains(set, 40));
  assert(hm_len(set) == 5);
  hm_insert(&z, set, 20);
  assert(hm_len(set) == 5);
  assert(hm_contains(set, 40));

  assert(hm_geti(set, 20) == 2);
  assert(hm_geti(set, 10) == 1);
  assert(hm_geti(set, 1) == 0);
  assert(hm_geti(set, 100) == -1);

  hm_del(set, 20);
  assert(hm_len(set) == 4);
  assert(!hm_contains(set, 20));
  assert(hm_contains(set, 1));
  assert(hm_contains(set, 10));
  assert(hm_contains(set, 30));
  assert(hm_contains(set, 40));
  hm_del(set, 1);
  assert(hm_contains(set, 10));
  assert(hm_contains(set, 30));
  assert(hm_contains(set, 40));
  hm_del(set, 30);
  assert(hm_getp_null(set, 30) == nullptr);
  assert(hm_gets(set, 10).key == 10);
  assert(hm_contains(set, 10));
  assert(hm_contains(set, 40));
  hm_del(set, 40);
  assert(hm_contains(set, 10));
  assert(!hm_contains(set, 40));
  hm_del(set, 10);
  assert(!hm_del(set, 10));

  struct {
    int key;
    int value;
  } *map = nullptr;

  hm_put(&z, map, 10, 100);
  hm_put(&z, map, 20, 200);
  assert(hm_getv(map, 10) == 100);
  assert(hm_getp_null(map, 20)->value == 200);

  // Test string-keyed hash tables.
  struct {
    char* key;
    int value;
  } *smap = nullptr;

  char* foo = "foobar";
  sh_insert(&z, smap, foo);
  assert(sh_contains(smap, foo));

  // Double check that we're not just comparing char* pointers.
  char foo2[7] = {0};
  memcpy(foo2, foo, 6);

  assert(sh_contains(smap, foo2));
  sh_insert(&z, smap, foo2);
  sh_del(smap, foo2);
  assert(0 == sh_len(smap));

  zone_free(&z);
}
*/
