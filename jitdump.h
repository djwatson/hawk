#pragma once

#include <stdint.h> // for uint64_t
#include <string>   // for string

void jit_dump_close();
void jit_dump_init();
void jit_dump(int len, uint64_t fn, const std::string& name);
void perf_map(uint64_t fn, uint64_t len, const std::string& name);
void jit_reader_add(int len, uint64_t fn, int i, uint64_t p, const std::string& name);
