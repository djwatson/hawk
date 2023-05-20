#pragma once

#include <string>

void jit_dump_close();
void jit_dump_init();
void jit_dump(int len, uint64_t fn, std::string name);
void perf_map(uint64_t fn, uint64_t len, std::string name);
void jit_reader_add(int len, uint64_t fn, int i, uint64_t p, std::string name);
