// Copyright 2023 Dave Watson

#include "parallel_copy.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"
// Simple version from
// "Tilting at Windmills with Coq: Formal Verification of a Compilation
// Algorithm for Parallel Moves"

// It's n^2 and uses recursion, but our max reg size is < 32 anyway,
// and usually closer to ~5.
typedef enum : uint8_t {
  TO_MOVE = 0,
  BEING_MOVED = 1,
  MOVED = 2,
} status;

static void move_one(int i, size_t len, par_copy *moves, status *s,
                     par_copy **res, uint64_t tmp) {
  assert(s[i] == TO_MOVE);
  if (moves[i].from == moves[i].to) {
    s[i] = MOVED;
    return;
  }
  s[i] = BEING_MOVED;
  for (int j = 0; j < len; j++) {
    if (moves[j].from == moves[i].to) {
      auto j_status = s[j];
      switch (j_status) {
      case TO_MOVE:
        move_one(j, len, moves, s, res, tmp);
        break;
      case BEING_MOVED:
        par_copy copy = {.from = moves[j].from, .to = tmp};
        arrput(*res, copy);
        moves[j].from = tmp;
        break;
      case MOVED:
        break;
      }
    }
  }
  par_copy copy = {.from = moves[i].from, .to = moves[i].to};
  arrput(*res, copy);
  s[i] = MOVED;
}

par_copy *serialize_parallel_copy(par_copy *moves, uint64_t tmp_reg) {
  auto len = arrlen(moves);
  status *s = calloc(sizeof(status), len);
  par_copy *res = nullptr;

  for (int i = 0; i < len; i++) {
    if (s[i] == TO_MOVE) {
      move_one(i, len, moves, s, &res, tmp_reg);
    }
  }

  free(s);
  return res;
}

/*
void run_test(uint64_t *input, size_t len) {
  par_copy *moves = nullptr;
  size_t pos = 0;
  for (size_t i = 0; i < len; i++) {
    par_copy mov = {.from = input[pos], .to = input[pos + 1]};
    pos += 2;
    arrput(moves, mov);
  }
  auto res = serialize_parallel_copy(moves, 15);
  arr_for_each(res, m) { printf("MOVE: %li to %li\n", m.from, m.to); }
  arrfree(moves);
  arrfree(res);
  printf("\n");
}

int main() {

  // trivial case
  {
    uint64_t test[] = {1, 0, 2, 1, 3, 2};
    run_test(test, 3);
  }
  // self loop optimized away
  {
    uint64_t test[] = {0, 0};
    run_test(test, 1);
  }
  // loop of 2
  {
    uint64_t test[] = {0, 1, 1, 0};
    run_test(test, 2);
  }
  // loop of 3
  {
    uint64_t test[] = {2, 1, 3, 2, 1, 3};
    run_test(test, 3);
  }
  // loop of 4
  {
    uint64_t test[] = {2, 1, 3, 2, 1, 4, 4, 3};
    run_test(test, 4);
  }
  // loop of 5
  {
    uint64_t test[] = {2, 1, 3, 2, 1, 4, 4, 5, 5, 3};
    run_test(test, 5);
  }
  // two loops of 2
  {
    uint64_t test[] = {1, 0, 0, 1, 2, 3, 3, 2};
    run_test(test, 4);
  }
  // simple fan out
  {
    uint64_t test[] = {1, 2, 1, 3};
    run_test(test, 2);
  }
  // more complex fan out
  {
    uint64_t test[] = {1, 2, 2, 3, 3, 1, 3, 4};
    run_test(test, 4);
  }
  // overlapping tmp
  {
    uint64_t test[] = {3, 1, 1, 3, 2, 4};
    run_test(test, 3);
  }
  // multiple from
  {
    uint64_t test[] = {8, 11, 5, 9, 2, 8, 5, 2, 2, 1};
    run_test(test, 5);
  }
}

*/
