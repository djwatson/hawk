// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h> // for uint64_t

void jit_dump_close();
void jit_dump_init();
void jit_dump(int len, uint64_t fn, const char *name);
void perf_map(uint64_t fn, uint64_t len, const char *name);
void jit_reader_add(int len, uint64_t fn);
