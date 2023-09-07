// This is a stub library to generate exe's for compiled boom programs.
// It is not used in the 'boom' executable itself.

#include <stdbool.h> // for bool, false, true
#include <stdio.h>   // for printf
#include <stdlib.h>  // for exit
#include <string.h>  // for strcmp, strcpy, strlen

#include "gc.h" // for GC_init
#include "bytecode.h"
#include "readbc.h"       // for readbc_file, readbc_image
#include "symbol_table.h" // for symbol_table_find_cstr
#include "types.h"        // for from_c_str, symbol, CLOSURE_TAG, TRUE_REP
#include "vm.h"           // for run

#include "record.h"

#define auto __auto_type
#define nullptr NULL

extern bool jit_dump_flag;

__attribute__((weak)) unsigned char exe_scm_bc[0];
__attribute__((weak)) unsigned int exe_scm_bc_len;

extern int joff;

static bool list = false;
extern unsigned TRACE_MAX;

extern bool verbose;
extern size_t page_cnt;
int main(int argc, char *argv[]) {


  GC_init();
  joff = 1;
  load_bootstrap();
  
  {
    joff = 0;
    auto *start_func = readbc_image(exe_scm_bc, exe_scm_bc_len);
    run(start_func, 0, nullptr);
  }

  free_trace();
  free_script();
  free_vm();

  return 0;
}
