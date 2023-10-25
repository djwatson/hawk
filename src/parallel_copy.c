// Copyright 2023 Dave Watson

#include "parallel_copy.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "defs.h"
#include "third-party/cwisstable.h"
#include "third-party/stb_ds.h"
#include "vec.h"

/* serialize parallel copy implementation, based on
 * https://github.com/pfalcon/parcopy
 * Allows fan out, does not allow fan in / dst smashing.
 */

VEC_TYPE_IMPL(u64, uint64_t);
CWISS_DECLARE_FLAT_HASHMAP(MyIntMap, uint32_t, uint32_t); //!OCLINT // NOLINT

static void map_insert(MyIntMap *m, uint32_t key, uint32_t v) {
  MyIntMap_Entry entry = {key, v};
  auto res = MyIntMap_insert(m, &entry);
  if (!res.inserted) {
    auto k = MyIntMap_Iter_get(&res.iter);
    assert(k);
    assert(k->key == key);
    k->val = v;
  }
}

par_copy *serialize_parallel_copy(par_copy *moves, uint64_t tmp_reg) {
  par_copy *moves_out = NULL;

  uint64_t *ready = NULL;

  auto rmoves = MyIntMap_new(arrlen(moves));
  auto loc = MyIntMap_new(arrlen(moves));

  for (uint64_t i = 0; i < arrlen(moves); i++) {
    uint32_t from = moves[i].from;
    uint32_t to = moves[i].to;
    // Check tmp is really a tmp reg.
    assert(from != tmp_reg);
    assert(to != tmp_reg);
    // Check for dest-smashing.
    assert(!MyIntMap_contains(&rmoves, &to));
    map_insert(&rmoves, to, from);
    map_insert(&loc, from, from);
  }
  for (uint64_t i = 0; i < arrlen(moves); i++) {
    uint32_t key = moves[i].to;
    if (!MyIntMap_contains(&loc, &key)) {
      arrpush_u64(&ready, moves[i].to);
    }
  }

  while (MyIntMap_size(&rmoves) != 0) {
    while (arrlen_u64(ready)) {
      uint32_t r = arrpop_u64(ready);
      auto it = MyIntMap_find(&rmoves, &r);
      auto k = MyIntMap_Iter_get(&it);
      if (k == NULL) {
        continue;
      }
      auto work_to = k->val;
      auto it2 = MyIntMap_cfind(&loc, &work_to);
      auto rmove_to = MyIntMap_CIter_get(&it2)->val;
      arrput(moves_out, ((par_copy){rmove_to, r}));
      map_insert(&loc, work_to, r);

      MyIntMap_erase_at(it);

      arrpush_u64(&ready, rmove_to);
    }
    if (MyIntMap_size(&rmoves) == 0) {
      break;
    }

    // There is a cycle, set one to tmp.

    // Fetch any from rmoves.
    auto it = MyIntMap_iter(&rmoves);
    auto k = MyIntMap_Iter_get(&it);
    auto from = k->val;
    auto to = k->key;
    MyIntMap_erase_at(it);

    if (from != to) {
      arrput(moves_out, ((par_copy){from, tmp_reg}));

      map_insert(&loc, tmp_reg, tmp_reg);
      arrpush_u64(&ready, from);

      map_insert(&rmoves, to, tmp_reg);
    }
  }
  MyIntMap_destroy(&rmoves);
  MyIntMap_destroy(&loc);
  arrfree_u64(&ready);

  return moves_out;
}

/*
uint64_t tmp = 101;
map moves;
map expected;
void run_test() {
  map res;
  serialize_parallel_copy(&moves, &res, tmp);
  if (res.mp_sz != expected.mp_sz ||
      memcmp(res.mp, expected.mp, sizeof(par_copy)*expected.mp_sz) !=0) {
    printf("Got:\n");
    for (uint64_t i = 0; i < res.mp_sz; i++) {
      printf("Mov %li to %li\n", res.mp[i].from, res.mp[i].to);
    }
    printf("Expected:\n");
    for (uint64_t i = 0; i < expected.mp_sz; i++) {
      printf("Mov %li to %li\n", expected.mp[i].from, expected.mp[i].to);
    }
    assert(0);
  }

  map_init(&moves);
  map_init(&expected);
}

int main() {
  map_init(&moves);
  map_init(&expected);

  // Trivial case
  tmp = 101;
  map_insert(&moves, 1, 0);
  map_insert(&moves, 2, 1);
  map_insert(&moves, 3, 2);
  map_insert(&expected, 1, 0);
  map_insert(&expected, 2, 1);
  map_insert(&expected, 3, 2);
  run_test();

  // Self loop optimized away
  tmp = 1;
  map_insert(&moves, 0, 0);
  run_test();

  // Loop with 2
  tmp = 2;
  map_insert(&moves, 0, 1);
  map_insert(&moves, 1, 0);
  map_insert(&expected, 0, tmp);
  map_insert(&expected, 1, 0);
  map_insert(&expected, tmp, 1);
  run_test();

  // Loop with 3
  tmp = 0;
  map_insert(&moves, 2, 1);
  map_insert(&moves, 3, 2);
  map_insert(&moves, 1, 3);
  map_insert(&expected, 2, tmp);
  map_insert(&expected, 3, 2);
  map_insert(&expected, 1, 3);
  map_insert(&expected, tmp, 1);
  run_test();


  // Two loops of 2
  tmp = 4;
  map_insert(&moves, 1, 0);
  map_insert(&moves, 0, 1);
  map_insert(&moves, 2, 3);
  map_insert(&moves, 3, 2);
  map_insert(&expected, 1, tmp);
  map_insert(&expected, 0, 1);
  map_insert(&expected, tmp, 0);
  map_insert(&expected, 2, tmp);
  map_insert(&expected, 3, 2);
  map_insert(&expected, tmp, 3);

  run_test();

  // Simple fan out
  tmp = 4;
  map_insert(&moves, 1, 2);
  map_insert(&moves, 1, 3);
  map_insert(&expected, 1, 3);
  map_insert(&expected, 3, 2);

  run_test();

  // More complex fan out
  tmp = 5;
  map_insert(&moves, 4, 1);
  map_insert(&moves, 1, 2);
  map_insert(&moves, 1, 3);
  map_insert(&moves, 3, 4);
  map_insert(&expected, 1, 2);
  map_insert(&expected, 4, 1);
  map_insert(&expected, 3, 4);
  map_insert(&expected, 2, 3);

  run_test();

  // More complex fan out
  tmp = 0;
  map_insert(&moves, 1, 2);
  map_insert(&moves, 2, 3);
  map_insert(&moves, 3, 1);
  map_insert(&moves, 3, 4);
  map_insert(&expected, 3, 4);
  map_insert(&expected, 2, 3);
  map_insert(&expected, 1, 2);
  map_insert(&expected, 4, 1);
  run_test();

  // Overlapping tmp
  tmp = 5;
  map_insert(&moves, 3, 1);
  map_insert(&moves, 1, 3);
  map_insert(&moves, 2, 4);
  map_insert(&expected, 2, 4);
  map_insert(&expected, 3, tmp);
  map_insert(&expected, 1, 3);
  map_insert(&expected, tmp, 1);

  run_test();

  // Multiple from
  tmp = 15;
  map_insert(&moves, 8, 11);
  map_insert(&moves, 5, 9);
  map_insert(&moves, 2, 8);
  map_insert(&moves, 5, 2);
  map_insert(&moves, 2, 1);
  map_insert(&expected, 2, 1);
  map_insert(&expected, 5, 2);
  map_insert(&expected, 2, 9);
  map_insert(&expected, 8, 11);
  map_insert(&expected, 1, 8);

  run_test();

  return 0;
}

*/
