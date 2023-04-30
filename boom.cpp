// error checking bytecode reader
// remove indirection through vector, func directly points to array
// remove consts:
//    various tags

// TODO:
// recording
// super-simple jit: sum, fib, ack, tak

#include "readbc.h"
#include "vm.h"

int main() {
  readbc();
  run();
  for (auto &func : funcs) {
    delete func;
  }
  for (auto &s : symbol_table) {
    delete s.second;
  }
  return 0;
}
