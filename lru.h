#pragma once

#define LRU_SIZE 16

typedef struct {
  uint8_t next;
  uint8_t prev;
} lrunode;

typedef struct {
  lrunode data[LRU_SIZE];
  uint8_t head;
} lru;


void lru_init(lru *l);
void lru_remove(lru *l, uint8_t node);
void lru_insert_before(lru *l, uint8_t node, uint8_t next);
void lru_poke(lru *l, uint8_t node);
uint8_t lru_oldest(lru *l);
