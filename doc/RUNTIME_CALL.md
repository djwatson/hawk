# Generic Fast Runtime Call Opcode

## Summary

Replace the per-primitive opcode expansion from `5f06315` with one generic
fast-call opcode, e.g. `RUNTIME_CALL`. The compiler lowers selected literal
`sys:FOREIGN_CALL` signatures to this opcode, avoiding libffi/signature parsing
in the VM without adding `ASSQ`, `EQUAL`, `LENGTH`, `LISTP`, `STRING_COPY`, etc.
as separate bytecodes and JIT IR ops.

## Key Changes

- Add one bytecode opcode: `RUNTIME_CALL` using `AD` layout.
- Use `instr.reg` as both argument base and destination, matching current
  contiguous argument lowering.
- Use `instr.data` as an enum ID into a small C runtime-call descriptor table.
- Keep Scheme surface code as `sys:FOREIGN_CALL`; no new `sys:LISTP`,
  `sys:EQUAL`, etc. symbols needed.
- In bytecode compilation, special-case only quoted, known signatures:
  `SCM_LISTP`, `SCM_EQUAL`, `SCM_STR_COPY`, and optionally `SCM_LENGTH` /
  `SCM_ASSQ` if those are intentionally moved back from Scheme to C.
- Unknown or dynamic `FOREIGN_CALL` signatures continue to emit normal
  `FOREIGN_CALL`.

## Implementation Shape

- Add a C descriptor table with ID, argc, argument/result convention, and direct
  function pointer/wrapper.
- VM handler does:
  - load descriptor by `instr.data`
  - call `fn1`, `fn2`, or `fn5` based on descriptor argc
  - store result to `stack[instr.reg]`
  - dispatch next opcode
- Recorder adds one generic `IR_RUNTIME_CALL` instead of N `IR_VM...` entries.
- JIT emitter handles `IR_RUNTIME_CALL` generically using the same C descriptor
  table and existing `IR_CARG` chain logic.
- This avoids the large duplicated changes in `bc.h`, `lib/expander-init.scm`,
  runtime Scheme wrappers, per-op recorder cases, per-op IR enum entries,
  regalloc VM-call lists, and emit target switches.

## Test Plan

- Build: `cmake --build build`.
- Run existing VM/runtime tests that cover `list?`, `equal?`, string
  copy/append/substring, and bootstrapping.
- Compare interpreter benchmark times against:
  - current `FOREIGN_CALL`
  - commit `5f06315`
  - new generic `RUNTIME_CALL`
- Acceptance target: VM time should be close to `5f06315`; if the extra
  descriptor switch is measurable, specialize only by arity with
  `RUNTIME_CALL1`, `RUNTIME_CALL2`, `RUNTIME_CALL5`.

## Assumptions

- The main performance issue is `do_foreign_call`: repeated signature parsing,
  `dlsym`, `ffi_prep_cif`, and `ffi_call`.
- A single extra descriptor lookup/switch is acceptable compared with libffi
  overhead.
- Public Scheme API should stay unchanged; this is a compiler/VM lowering
  optimization, not a new user-visible primitive set.
