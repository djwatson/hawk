#include <string.h>

long memcpy_double(double arg) {
  long res;
  memcpy(&res, &arg, sizeof(res));
  return res;
}
