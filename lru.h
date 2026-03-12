// Copyright 2023 Dave Watson

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "asm.h"

#define LRU_SIZE 32

typedef struct {
  uint16_t value;
  uint8_t prev;
  uint8_t next;
  bool linked;
} lru_node;

typedef struct {
  lru_node nodes[LRU_SIZE];
  uint8_t head;
  uint8_t count;
} lru;

static_assert(LRU_SIZE >= GPR_ALLOCATABLE,
              "lru capacity must fit allocatable GPRs");
static_assert(LRU_SIZE >= FPR_ALLOCATABLE,
              "lru capacity must fit allocatable FPRs");

void lru_init(lru *l);
void lru_add(lru *l, uint16_t value);
void lru_remove(lru *l, uint16_t value);
void lru_poke(lru *l, uint16_t value);
uint16_t lru_pop_oldest(lru *l);
