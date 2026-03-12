// Copyright 2023 Dave Watson

#include "lru.h"

#include <assert.h>
#include <stdlib.h>

/// Dead-simple LRU cache, implemented as a doubly-linked list with a static
/// backing array.
///
///              <-- prev next -->
///      -------      -------      -------      --------
///      |  a  | <--> |  b  | <--> |  c  | <--> | head | <--|
///      -------      -------      -------      --------    |
///         ^                       oldest       newest     |
///         |-----------------------------------------------|

static uint8_t find_node(lru *l, uint16_t value) {
  for (uint8_t i = 0; i < LRU_SIZE; i++) {
    if (l->nodes[i].linked && l->nodes[i].value == value) {
      return i;
    }
  }
  return UINT8_MAX;
}

static uint8_t alloc_node(lru *l) {
  for (uint8_t i = 0; i < LRU_SIZE; i++) {
    if (!l->nodes[i].linked) {
      return i;
    }
  }
  abort();
}

static void unlink_node(lru *l, uint8_t idx) {
  auto node = &l->nodes[idx];
  assert(node->linked);

  if (l->count == 1) {
    l->head = UINT8_MAX;
  } else {
    l->nodes[node->prev].next = node->next;
    l->nodes[node->next].prev = node->prev;
    if (l->head == idx) {
      l->head = node->prev;
    }
  }

  node->linked = false;
  node->prev = UINT8_MAX;
  node->next = UINT8_MAX;
  l->count--;
}

static void append_newest(lru *l, uint8_t idx, uint16_t value) {
  auto node = &l->nodes[idx];
  node->value = value;
  node->linked = true;
  if (!l->count) {
    node->prev = idx;
    node->next = idx;
  } else {
    uint8_t old_head = l->head;
    uint8_t oldest = l->nodes[old_head].next;
    node->prev = old_head;
    node->next = oldest;
    l->nodes[old_head].next = idx;
    l->nodes[oldest].prev = idx;
  }
  l->head = idx;
  l->count++;
}

void lru_init(lru *l) {
  l->head = UINT8_MAX;
  l->count = 0;
  for (uint8_t i = 0; i < LRU_SIZE; i++) {
    l->nodes[i].linked = false;
    l->nodes[i].prev = UINT8_MAX;
    l->nodes[i].next = UINT8_MAX;
  }
}

void lru_add(lru *l, uint16_t value) {
  if (find_node(l, value) != UINT8_MAX) {
    return;
  }
  append_newest(l, alloc_node(l), value);
}

void lru_remove(lru *l, uint16_t value) {
  uint8_t idx = find_node(l, value);
  if (idx == UINT8_MAX) {
    return;
  }
  unlink_node(l, idx);
}

void lru_poke(lru *l, uint16_t value) {
  uint8_t idx = find_node(l, value);
  if (idx == UINT8_MAX) {
    lru_add(l, value);
    return;
  }
  if (idx == l->head) {
    return;
  }
  unlink_node(l, idx);
  append_newest(l, idx, value);
}

uint16_t lru_pop_oldest(lru *l) {
  if (!l->count) {
    abort();
  }
  uint8_t idx = l->nodes[l->head].next;
  uint16_t value = l->nodes[idx].value;
  unlink_node(l, idx);
  return value;
}

#if LRU_TEST

int main(void) {
  lru l;
  lru_init(&l);

  // Single-node add/poke/pop should preserve count and round-trip the value.
  lru_add(&l, 7);
  assert(l.count == 1);
  lru_poke(&l, 7);
  assert(l.count == 1);
  assert(lru_pop_oldest(&l) == 7);
  assert(l.count == 0);

  // Duplicate adds should be ignored.
  lru_add(&l, 5);
  lru_add(&l, 5);
  assert(l.count == 1);
  assert(lru_pop_oldest(&l) == 5);
  assert(l.count == 0);

  // Basic FIFO order: oldest value should pop first.
  lru_add(&l, 1);
  lru_add(&l, 2);
  lru_add(&l, 3);
  assert(l.count == 3);
  assert(lru_pop_oldest(&l) == 1);
  assert(l.count == 2);

  // Removing a middle node and poking remaining nodes should keep order sane.
  lru_add(&l, 4);
  lru_remove(&l, 3);
  assert(l.count == 2);
  lru_poke(&l, 2);
  lru_poke(&l, 4);
  assert(lru_pop_oldest(&l) == 2);
  assert(lru_pop_oldest(&l) == 4);
  assert(l.count == 0);

  // Removing a missing value should be a no-op.
  lru_add(&l, 20);
  lru_add(&l, 21);
  lru_remove(&l, 99);
  assert(l.count == 2);
  assert(lru_pop_oldest(&l) == 20);
  assert(lru_pop_oldest(&l) == 21);
  assert(l.count == 0);

  // Poking a missing value should behave like add.
  lru_poke(&l, 30);
  assert(l.count == 1);
  assert(lru_pop_oldest(&l) == 30);
  assert(l.count == 0);

  // Removing the head/newest should leave the older nodes intact.
  lru_add(&l, 1);
  lru_add(&l, 2);
  lru_add(&l, 3);
  lru_remove(&l, 3);
  assert(l.count == 2);
  assert(lru_pop_oldest(&l) == 1);
  assert(lru_pop_oldest(&l) == 2);
  assert(l.count == 0);

  // Removing the oldest should keep the remaining newer order intact.
  lru_add(&l, 1);
  lru_add(&l, 2);
  lru_add(&l, 3);
  lru_remove(&l, 1);
  assert(l.count == 2);
  assert(lru_pop_oldest(&l) == 2);
  assert(lru_pop_oldest(&l) == 3);
  assert(l.count == 0);

  // Repeated pokes of the same node should not duplicate or reshuffle badly.
  lru_add(&l, 1);
  lru_add(&l, 2);
  lru_add(&l, 3);
  lru_poke(&l, 2);
  lru_poke(&l, 2);
  assert(lru_pop_oldest(&l) == 1);
  assert(lru_pop_oldest(&l) == 3);
  assert(lru_pop_oldest(&l) == 2);
  assert(l.count == 0);

  // Removing, reusing capacity, and then poking should maintain correct order.
  lru_add(&l, 1);
  lru_add(&l, 2);
  lru_add(&l, 3);
  lru_remove(&l, 2);
  lru_add(&l, 4);
  lru_poke(&l, 1);
  assert(lru_pop_oldest(&l) == 3);
  assert(lru_pop_oldest(&l) == 4);
  assert(lru_pop_oldest(&l) == 1);
  assert(l.count == 0);

  // Mixed poke/remove/pop on several nodes should preserve recency semantics.
  lru_add(&l, 10);
  lru_add(&l, 11);
  lru_add(&l, 12);
  lru_poke(&l, 10);
  assert(lru_pop_oldest(&l) == 11);
  lru_remove(&l, 10);
  assert(l.count == 1);
  assert(lru_pop_oldest(&l) == 12);
  assert(l.count == 0);

  // Filling the entire fixed-capacity LRU should still pop in insertion order.
  for (uint16_t i = 0; i < LRU_SIZE; i++) {
    lru_add(&l, i);
  }
  assert(l.count == LRU_SIZE);
  for (uint16_t i = 0; i < LRU_SIZE; i++) {
    assert(lru_pop_oldest(&l) == i);
  }
  assert(l.count == 0);

  return 0;
}
#endif
