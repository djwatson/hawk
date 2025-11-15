#include "bc.h"

char *bc_names[] = {
#define X(name, type) #name,
    OPS
#undef X
};
