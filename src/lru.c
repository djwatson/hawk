// Copyright 2023 Dave Watson

#include "lru.h"

/// Dead-simple LRU cache, implemented as a doubly-linked list with a static
/// backing array.
///
///              <-- prev next -->
///      -------      -------      -------      --------
///      |  a  | <--> |  b  | <--> |  c  | <--> | head | <--|
///      -------      -------      -------      --------    |
///         ^                       oldest       newest     |
///         |-----------------------------------------------|

void lru_init(lru *l) {
  l->head = 0;
  l->data[0].next = 1;
  l->data[0].prev = LRU_SIZE - 1;
  for (int16_t i = 1; i < LRU_SIZE; i++) {
    l->data[i].next = (i + 1) % LRU_SIZE;
    l->data[i].prev = i - 1;
  }
}

void lru_remove(lru *l, uint8_t node) {
  // Assumes size is always > 1
  l->data[l->data[node].prev].next = l->data[node].next;
  l->data[l->data[node].next].prev = l->data[node].prev;
}

void lru_insert_before(lru *l, uint8_t node, uint8_t next) {
  uint8_t prev = l->data[next].prev;
  l->data[prev].next = node;
  l->data[next].prev = node;
  l->data[node] = (lrunode){next, prev};
}

void lru_poke(lru *l, uint8_t node) {
  uint8_t prev_newest = l->head;
  if (node == prev_newest) {
    return;
  } else if (l->data[prev_newest].prev != node) {
    lru_remove(l, node);
    lru_insert_before(l, node, l->head);
  }
  l->head = node;
}

uint8_t lru_oldest(lru *l) {
  uint8_t out = l->data[l->head].prev;
  l->head = out;

  return out;
}

#if 0
#include <stdio.h>
int main() {
  lru l;
  lru_init(&l);
  printf("Oldest %i\n", lru_oldest(&l));
  printf("Oldest %i\n", lru_oldest(&l));
  lru_poke(&l, 3);
  lru_poke(&l, 2);
  lru_poke(&l, 3);
  lru_poke(&l, 1);
  lru_poke(&l, 1);
  lru_poke(&l, 3);
  lru_poke(&l, 0);
  lru_poke(&l, 2);
  printf("Oldest %i\n", lru_oldest(&l));
  return 0;
}
#endif
