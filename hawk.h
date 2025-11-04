#pragma once

// Just some helper macros

#ifdef __clang__
#define MUSTTAIL __attribute__((musttail))
#define PRESERVE_NONE // __attribute__((preserve_none))
#else
#define MUSTTAIL
#define PRESERVE_NONE
#endif

#define BCFUNC_FLEXARRAY_DIAG_PUSH                                             \
  _Pragma("clang diagnostic push") _Pragma(                                    \
      "clang diagnostic ignored \"-Wgnu-variable-sized-type-not-at-end\"")
#define BCFUNC_FLEXARRAY_DIAG_POP _Pragma("clang diagnostic pop")
