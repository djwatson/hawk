#pragma once

// Just some helper macros

#ifdef __clang__
#define MUSTTAIL __attribute__((musttail))
#define PRESERVE_NONE // __attribute__((preserve_none))
#else
#define MUSTTAIL
#define PRESERVE_NONE
#endif

#define NOINLINE __attribute__((noinline))
#define INLINE __attribute__((always_inline))
#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)
#define ALIGNED8 __attribute__((aligned(8)))
#define EXPORT __attribute__((visibility("default")))
#define SWAP(type, a, b)                                                       \
  do {                                                                         \
    type SWAP_tmp = (a);                                                       \
    (a) = (b);                                                                 \
    (b) = SWAP_tmp;                                                            \
  } while (0)
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

#define BCFUNC_FLEXARRAY_DIAG_PUSH                                             \
  _Pragma("clang diagnostic push") _Pragma(                                    \
      "clang diagnostic ignored \"-Wgnu-variable-sized-type-not-at-end\"")
#define BCFUNC_FLEXARRAY_DIAG_POP _Pragma("clang diagnostic pop")
