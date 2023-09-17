#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct{
  int64_t key;
  uint64_t value;
} uf_item;

typedef struct {
  uint64_t parent;
  uint64_t sz;
} box;

typedef struct uf_s {
  // Map values contain indexes into table.
  uf_item* map;
  uint64_t map_cnt;
  uint64_t map_sz;
  // Table parent is index to table.
  // If it == self, it has no parent.
  box* table;
} uf;

void uf_init(uf* ht);
void uf_free(uf* ht);
bool unionfind( uf* ht, int64_t x, int64_t y);
