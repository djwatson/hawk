# Chez-Like Native Port Strategy

## Summary

Replace the Scheme `port` record in `lib/runtime.scm` with a native heap object whose first word encodes both the port type and stable port flags, following Chez's strategy. Keep the public R7RS Scheme API unchanged, but lower selected port operations through `RUNTIME_CALL` so the VM avoids libffi and the recorder/JIT can recognize fast port primitives.

The goal is to remove hot trace bloat from record predicates/accessors (`port?`, `port-open?`, `port-kind`, `port-pos`, `port-len`, `port-buf`, setters) and make common buffered character/byte I/O compile to direct field loads/stores with a runtime slow path only when the buffer is empty/full or the port is invalid.

## Port Representation

Use a `PTR_TAG` heap object with a fixed-size `port_s`. Store port identity and flags in `header.type`, not in Scheme fields:

```c
typedef enum : uint64_t {
  PORT_TAG = 0x51,          // new PTR_TAG-compatible heap type
  PORT_TAG_MASK = 0xff,
  PORT_FLAG_SHIFT = 8,

  PORT_INPUT = UINT64_C(1) << PORT_FLAG_SHIFT,
  PORT_OUTPUT = UINT64_C(2) << PORT_FLAG_SHIFT,
  PORT_BINARY = UINT64_C(4) << PORT_FLAG_SHIFT,
  PORT_CLOSED = UINT64_C(8) << PORT_FLAG_SHIFT,
  PORT_EOF = UINT64_C(0x10) << PORT_FLAG_SHIFT,
  PORT_FILE = UINT64_C(0x20) << PORT_FLAG_SHIFT,
  PORT_FOLD_CASE = UINT64_C(0x40) << PORT_FLAG_SHIFT,
  PORT_NO_FOLD_CASE = UINT64_C(0x80) << PORT_FLAG_SHIFT,

  PORT_TEXT_INPUT = PORT_TAG | PORT_INPUT,
  PORT_TEXT_OUTPUT = PORT_TAG | PORT_OUTPUT,
  PORT_BINARY_INPUT = PORT_TAG | PORT_INPUT | PORT_BINARY,
  PORT_BINARY_OUTPUT = PORT_TAG | PORT_OUTPUT | PORT_BINARY,
} port_type;

typedef struct port_s {
  gc_header header;
  int32_t fd;      // -1 for string/bytevector ports
  uint32_t pos;    // next input/output index
  uint32_t len;    // readable bytes/chars or buffered output length
  uint32_t cap;    // buffer capacity
  gc_obj buf;      // input buffer or output file buffer
  gc_obj sbuf;     // string/bytevector output accumulator, or #f
} port_s;
```

Predicate checks should be mask-and-compare:

```c
is_port(x):         is_ptr(x) && (to_port(x)->header.type & PORT_TAG_MASK) == PORT_TAG
input-port?:        is_port(x) && (type & PORT_INPUT)
output-port?:       is_port(x) && (type & PORT_OUTPUT)
binary-port?:       is_port(x) && (type & PORT_BINARY)
textual-port?:      is_port(x) && !(type & PORT_BINARY)
open input?:        input-port? && !(type & PORT_CLOSED)
open output?:       output-port? && !(type & PORT_CLOSED)
```

Update GC size/trace/type-name handling for `PORT_TAG`; trace `buf` and `sbuf`.

## Runtime Calls And Fast Paths

Implement `RUNTIME_CALL` first, then map literal `sys:FOREIGN_CALL` signatures for ports to descriptor IDs. Unknown signatures still use normal `FOREIGN_CALL`.

Required runtime-call functions:

dave: ugh codex not quite. 

```c
these can all be in scheme still, with SCM_ALLOC giving the right tag
gc_obj scm_make_fd_port(gc_obj fd, gc_obj type);
gc_obj scm_make_input_string_port(gc_obj str);
gc_obj scm_make_output_string_port(void);
gc_obj scm_make_input_bytevector_port(gc_obj bv);
gc_obj scm_make_output_bytevector_port(void);

probably all in scheme still
gc_obj scm_port_predicate(gc_obj port, gc_obj mask, gc_obj want);
gc_obj scm_port_close(gc_obj port);
gc_obj scm_port_flush(gc_obj port);

I don't care about slowpaths, only fastpath checks!
gc_obj scm_port_read_char_slow(gc_obj port);
gc_obj scm_port_peek_char_slow(gc_obj port);
gc_obj scm_port_write_char_slow(gc_obj port, gc_obj ch);
gc_obj scm_port_read_u8_slow(gc_obj port);
gc_obj scm_port_peek_u8_slow(gc_obj port);
gc_obj scm_port_write_u8_slow(gc_obj port, gc_obj u8);

// still in scheme!
gc_obj scm_port_get_output_string(gc_obj port);
gc_obj scm_port_get_output_bytevector(gc_obj port);
```

The recorder/JIT should treat these port runtime calls specially:

dave: yea THESE need the optimization, based on new typechecks

- `peek-char`/`read-char`: if the argument is a known textual input port and `pos < len`, load from `buf` and optionally increment `pos`; otherwise call the slow runtime function.
- `peek-u8`/`read-u8`: same shape for binary input ports.
- `write-char`/`write-u8`: if the argument is a known matching output port and the active buffer has capacity, store directly and update `pos`/`len`; otherwise call the slow runtime function.
- Predicates (`port?`, `input-port?`, `output-port?`, `textual-port?`, `binary-port?`, open predicates) become masked checks on `header.type`.

The slow runtime functions handle validation, closed-port errors, file reads/writes, buffer refill/flush/growth, EOF flag updates, and error reporting.

## Scheme Surface

Keep R7RS names and arities in `lib/runtime.scm`, but make them thin wrappers:

- Constructors call native make-port runtime calls.
- Predicates call `scm_port_predicate` through `RUNTIME_CALL`-lowered `sys:FOREIGN_CALL`.
- `read-char`, `peek-char`, `read-u8`, `peek-u8`, `write-char`, and `write-u8` call the runtime-call entry points directly; the JIT recognizes these calls and emits the inline fast path.
- `read-string`, `read-bytevector`, `read-bytevector!`, `write-string`, and `write-bytevector` can initially remain Scheme loops over the primitive character/byte operations.
- Replace the current record-backed EOF object with the existing immediate `EOF_OBJ`, and make `eof-object?` a direct immediate predicate.

Keep `fold-case` as a port flag because the reader uses Chez-like fold/no-fold behavior, but do not implement full transcoder machinery in this pass.

## Implementation Notes

- Use strings for textual buffers and bytevectors for binary buffers. File binary ports should use bytevectors; file textual ports may use strings to keep `LOAD_CHAR` fast.
- Use `PORT_EOF` instead of `len = -1`; it avoids signed length state and matches Chez's explicit EOF flag.
- `close-port` sets `PORT_CLOSED`, clears `PORT_EOF`, flushes output ports, closes nonnegative fds, and clears buffer lengths.
- `char-ready?` and `u8-ready?` return true when `pos < len`; do not add blocking readiness probes in this pass.
- Keep custom ports/transcoders out of scope. The native object can grow later with a handler/info pair if needed, but the first pass should optimize the existing file/string/bytevector behavior.

## Test Plan

- Build with `cmake --build build`.
- Run the existing dynamic/read-heavy tests and compare the hottest trace before/after; expected shape is one port type check, direct `pos/len/buf` loads, direct char/byte load, and direct `pos` update on the fast path.
- Add focused tests for all port predicates, open/closed predicates, EOF object identity/predicate behavior, peek preserving position, read advancing position, EOF after buffer exhaustion, close/flush behavior, and wrong-kind errors.
- Test textual file, binary file, string input/output, and bytevector input/output round trips.
- Verify that `RUNTIME_CALL` lowering falls back to `FOREIGN_CALL` for unknown signatures and that port calls use descriptor IDs instead of libffi.

 Chez’s read-char fast path is essentially:

  p = argument_or_current_input;
  icount = p->icount;

  if (icount == 0)
    return slow_read_char(p);   // refill/check/EOF/handler path

  p->icount = icount + string_char_bytes;
  return load_char(p->ilast + icount);

  The slightly non-obvious part is that Chez’s port-icount is used like a negative offset/count relative to port-ilast, not like Hawk’s current pos. Empty
  is 0; while data remains, icount is negative. Consuming a char increments it toward zero. The loaded character address is:

  (%load t0 (%mref p port-ilast-disp) 0)

  where t0 is port-icount. See /home/davejwatson/projects/ChezScheme/s/cpprim.ss:4279.

  The inline expansion for textual input ports does this:

  (let ([e-icount (%mref e-p port-icount-disp)])
    (if (eq? e-icount 0)
        (slow-libcall e-p)
        (begin
          (set! e-icount (+ e-icount string-char-bytes))
          (load-char e-icount (%mref e-p port-ilast-disp)))))

