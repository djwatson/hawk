#include <stdint.h>

typedef struct bc bc;

typedef struct {
  union {
    int64_t value;
    bc *raddress;
    void *ptr;
  };
} gc_obj;

typedef struct gc_header {
  union {
    struct {
      uint32_t type;
      uint32_t rc;
    };
    uint64_t fwdtag;
  };
  struct gc_header *fwd;
} gc_header;

typedef struct bcfunc {
  gc_header header;
  gc_obj name;
  uint64_t const_cnt;
  uint64_t bc_cnt;
  // consts and bc are both pointers into data,
  // since we can have only a single flexible array member.
  // i.e. this is:
  // gc_obj[const_cnt];
  // bc[bc_cnt];
  uint8_t data[];
} bcfunc;
