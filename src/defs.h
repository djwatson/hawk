// Copyright 2023 Dave Watson

#pragma once

#define EXPORT __attribute__((visibility("default")))

#define auto __auto_type
#define nullptr NULL

#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)
#define NOINLINE __attribute__((noinline))
#define INLINE __attribute__((always_inline))
#define WEAK __attribute__((weak))
#define MAYBE_UNUSED __attribute__((unused))

#ifdef __clang__
#define MUSTTAIL __attribute__((musttail))
#else
#define MUSTTAIL
#endif
