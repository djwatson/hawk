#pragma once

#include <stdint.h> // for uint64_t

#ifdef __cplusplus
extern "C" {
#endif
void jit_dump_close();
void jit_dump_init();
void jit_dump(int len, uint64_t fn, const char* name);
void perf_map(uint64_t fn, uint64_t len, const char *name);
void jit_reader_add(int len, uint64_t fn, int i, uint64_t p,const char* name);
#ifdef __cplusplus
}
#endif
