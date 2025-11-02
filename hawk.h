#pragma once

// Just some helper macros

#define BCFUNC_FLEXARRAY_DIAG_PUSH                                             \
  _Pragma("clang diagnostic push") _Pragma(                                    \
      "clang diagnostic ignored \"-Wgnu-variable-sized-type-not-at-end\"")
#define BCFUNC_FLEXARRAY_DIAG_POP _Pragma("clang diagnostic pop")
