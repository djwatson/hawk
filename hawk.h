#pragma once

#include <stdint.h>

// Just some helper macros

#define MUSTTAIL __attribute__((musttail))
#define PRESERVE_NONE // __attribute__((preserve_none))

#define NOINLINE __attribute__((noinline))
#define INLINE __attribute__((always_inline))
#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)
#define ALIGNED8 __attribute__((aligned(8)))
#define EXPORT __attribute__((visibility("default")))
#if defined(__clang__)
#define IR_PRAGMA_DISABLE                                                      \
  _Pragma("clang diagnostic push")                                             \
      _Pragma("clang diagnostic ignored \"-Winitializer-overrides\"")
#define IR_PRAGMA_RESTORE _Pragma("clang diagnostic pop")
#else
#define IR_PRAGMA_DISABLE
#define IR_PRAGMA_RESTORE
#endif

#define SWAP(type, a, b)                                                       \
  do {                                                                         \
    type SWAP_tmp = (a);                                                       \
    (a) = (b);                                                                 \
    (b) = SWAP_tmp;                                                            \
  } while (0)
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define REG_ARG_CNT 6

#define BCFUNC_FLEXARRAY_DIAG_PUSH                                             \
  _Pragma("clang diagnostic push") _Pragma(                                    \
      "clang diagnostic ignored \"-Wgnu-variable-sized-type-not-at-end\"")
#define BCFUNC_FLEXARRAY_DIAG_POP _Pragma("clang diagnostic pop")

// global flags
extern bool verbose;
extern bool profile;
extern bool jit_dump_flag;
extern int64_t max_trace;
extern char *command_line_program_name;
extern int command_line_argc;
extern char **command_line_argv;
