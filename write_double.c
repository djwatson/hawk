#include <string.h>

long memcpy_double(double x) {
  long res;
  memcpy(&res, &x, sizeof(res));
  return res;
}
