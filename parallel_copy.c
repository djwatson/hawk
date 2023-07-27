// Copyright 2023 Dave Watson

#include "parallel_copy.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define REG_MAX 32

/* serialize parallel copy implementation, based on
 * https://github.com/pfalcon/parcopy
 * Allows fan out, does not allow fan in / dst smashing.
 */

static void map_init(map* m) {
  m->mp_sz = 0;
}

static par_copy* map_find(map* m, uint64_t needle) {
  for (uint64_t i = 0; i < m->mp_sz; i++) {
    if (m->mp[i].from == needle) {
      return &m->mp[i];
    }
  }

  return NULL;
}

static void map_erase(map* m, uint64_t needle) {
  for (uint64_t i = 0; i < m->mp_sz; i++) {
    if (m->mp[i].from == needle) {
      for (uint64_t j = i + 1; j < m->mp_sz; j++) {
        m->mp[j-1] = m->mp[j];
      }
      m->mp_sz--;
      break;
    }
  }
}

void map_insert(map* m, uint64_t key, uint64_t value) {
  if (m->mp_sz == MAX_MAP_SIZE) {
    printf("Hit max map size in parcopy\n");
    exit(-1);
  }
  m->mp[m->mp_sz].from = key;
  m->mp[m->mp_sz].to = value;
  m->mp_sz++;
}

static void map_set(map* m, uint64_t key, uint64_t value) {
  __auto_type v = map_find(m, key);
  if (v) {
    v->to = value;
  } else {
    map_insert(m, key, value);
  }
}

void serialize_parallel_copy(map* moves, map* moves_out, uint64_t tmp_reg) {
  map_init(moves_out);

  for (uint64_t i = 0; i < moves->mp_sz; i++) {
    assert(moves->mp[i].from != tmp_reg);
    assert(moves->mp[i].to != tmp_reg);
  }

  uint64_t ready[REG_MAX];
  uint64_t ready_pos = 0;

  map rmoves;
  map loc;
  map_init(&rmoves);
  map_init(&loc);

  for (uint64_t i = 0; i < moves->mp_sz; i++) {
    // Check for dest-smashing.
    assert(map_find(&rmoves, moves->mp[i].to) == NULL);
    map_insert(&rmoves, moves->mp[i].to, moves->mp[i].from);
    map_insert(&loc, moves->mp[i].from, moves->mp[i].from);
    if (map_find(moves, moves->mp[i].to) == NULL) {
      ready[ready_pos++] = moves->mp[i].to;
    }
  }

  while (rmoves.mp_sz != 0) {
    while (ready_pos != 0) {
      uint64_t r = ready[ready_pos-1];
      ready_pos--;
      if (map_find(&rmoves, r) == NULL) {
        continue;
      }
      __auto_type rmove = map_find(&loc, map_find(&rmoves, r)->to)->to;
      map_insert(moves_out, rmove, r);
      map_set(&loc, rmove, r);

      map_erase(&rmoves, r);

      ready[ready_pos++] = rmove;
    }
    if (rmoves.mp_sz == 0) {
      break;
    }

    __auto_type from = rmoves.mp[0].to;
    __auto_type to = rmoves.mp[0].from;
    map_erase(&rmoves, to);
    if (from != to) {
      // There is a cycle, set one to tmp.
      map_insert(moves_out, from, tmp_reg);

      map_set(&loc, tmp_reg, tmp_reg);
      ready[ready_pos++] = from;

      map_set(&rmoves, to, tmp_reg);
    }
  }
}

#if 0
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

  return 0;
}

#endif
