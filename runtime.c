#include <fcntl.h>

#include "ftoa.h"
#include "hawk.h"

EXPORT int32_t scm_open(char *name, uint8_t readonly) {
  return open(name, readonly ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0777);
}

EXPORT char *flonum_string(double d) { return ftoa_fast(d); }
