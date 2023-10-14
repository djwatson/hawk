#include "opcodes.h"

const char *ins_names[] = {
#define X(name, str) str,
    BYTECODE_INSTRUCTIONS
#undef X
};
