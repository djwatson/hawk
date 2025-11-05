#pragma once

#if defined(__aarch64__)
  #include "asm_aarch64.h"
#elif defined(__x86_64__)
  #include "asm_x64.h"
#else
  #error "Unsupported architecture"
#endif
