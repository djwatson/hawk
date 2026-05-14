# IR_ALLOC Sinking Plan

## Summary

Implement LuaJIT-style allocation sinking for `IR_ALLOC`. Sunk allocations and
their stores remain in the trace IR as virtual recipe instructions, tagged with
special register sentinel values. Snapshots do not need a new sunk-object data
structure: they keep normal `snap_entry.val` references, and exit/link/replay
code notices when the referenced IR value is `REG_SUNK` and recursively
materializes it from the retained IR.

The intended pass order is:

```c
dce(cur_trace);
sink_allocs(cur_trace);
dce(cur_trace);
emit(cur_trace, ...);
```

The second DCE must preserve virtual recipe IR even though it emits no normal
machine code.

## Representation

Add special non-register values alongside `REG_NONE`:

```c
REG_NONE = 0xff,  // no location
REG_SINK = 0xfe,  // sinkable recipe instruction, no emitted code
REG_SUNK = 0xfd,  // virtual value needed by at least one snapshot
```

Real registers remain `< MAX_REG`. Add helpers and use them anywhere code
currently treats `reg != REG_NONE` as a real register:

```c
static inline bool reg_is_real(uint8_t r) { return r < MAX_REG; }
static inline bool reg_is_sink(uint8_t r) { return r == REG_SINK; }
static inline bool reg_is_sunk(uint8_t r) { return r == REG_SUNK; }
static inline bool reg_is_virtual(uint8_t r) {
  return r == REG_SINK || r == REG_SUNK;
}
```

Meanings:

- `IR_ALLOC.reg = REG_SUNK`: allocation is virtual and may be referenced by
  snapshots.
- `IR_STORE.reg = REG_SINK`: store is part of a virtual object's reconstruction
  recipe.
- `IR_REF.reg = REG_SINK`: ref is part of a virtual object's store address
  recipe.
- Other IR that remains physically needed must retain ordinary register/spill
  behavior.

Do not add sunk metadata to `snap`. Snapshots continue to identify live values
with `snap_entry.val`; the referenced IR's register sentinel determines whether
normal `snap_entry_loc` or recursive unsinking is required.

## Sink Analysis

Add `opt_sink.c/.h` with `sink_allocs(trace *t)`.

Eligibility:

- Only consider `IR_ALLOC` initially.
- Require constant allocation type.
- Start with constant allocation size unless dynamic-size materialization is
  straightforward with existing allocation emission.
- References must be `IR_REF` with constant offsets.
- Stores must be `IR_STORE`, and optionally `IR_STORE_CHAR`/`IR_STORE_BYTE` for
  compatible string/bytevector allocations with constant offsets.

Reject an allocation if it is used by anything other than:

- `IR_REF` recipe nodes
- sinkable stores to that allocation
- snapshot entries
- field values of another sunk object
- loads that were already removed by store-to-load forwarding

Reject on:

- remaining `IR_LOAD`, `IR_LOAD_CHAR`, or `IR_LOAD_BYTE`
- dynamic references or offsets
- calls, VM calls, `IR_CCALL`, `IR_CARG`, or stack stores
- comparisons or other identity-observing uses
- stores into non-sunk/unknown objects
- `IR_GCLOG` that belongs to an escaping object

Marking algorithm:

1. Walk uses conservatively and mark non-sinkable allocations live.
2. For each unmarked eligible allocation, set `IR_ALLOC.reg = REG_SINK`.
3. Mark related `IR_REF` and store recipe instructions as `REG_SINK`.
4. Walk snapshots. If a snapshot references a `REG_SINK` allocation, promote it
   to `REG_SUNK`.
5. Recursively promote any virtual allocation stored into a field of a
   `REG_SUNK` allocation.

After sinking, DCE must:

- not mark a `REG_SUNK` snapshot value as requiring a real location
- still mark field values used by sunk stores as live
- preserve `REG_SUNK` allocations and `REG_SINK` recipe stores/refs as IR
  records for unsinking
- remove unrelated dead IR normally

## Unsinking And Emission

Add recursive materialization helpers in the emitter:

- `emit_unsink_value(trace *t, snap *sn, slot v, ...)`
- `emit_unsink_alloc(trace *t, snap *sn, uint16_t alloc_ref, ...)`
- `find_sunk_stores(trace *t, snap *sn, uint16_t alloc_ref, ...)`

Behavior:

- If a snapshot entry references a normal value, use existing
  `emit_snap_store_entry`.
- If it references `IR_ALLOC` with `reg == REG_SUNK`, materialize it instead of
  calling `snap_entry_loc`.
- Materialize each sunk allocation at most once per snapshot emission and reuse
  the resulting temporary/canonical stack value for duplicate references, so
  object identity is preserved.
- To reconstruct fields, scan retained IR before `sn->ir` for `REG_SINK` stores
  whose `IR_REF` base is the allocation being unsunk.
- Recursively unsink field values before storing them if they are also
  `REG_SUNK`.
- Reuse the existing `IR_ALLOC` header/allocation logic for object creation.
- Stores into the newly materialized object do not need `IR_GCLOG`, because the
  object is newly allocated.

Update snapshot/link helpers:

- `snap_entry_loc` must assert the value is not virtual.
- `collect_live_roots` must skip virtual snapshot entries as direct roots, but
  include real field values needed during unsinking allocation slow paths.
- `emit_snap_store_entry` must dispatch to unsinking for `REG_SUNK`.
- `collect_link_actions` must not generate `LINK_MOVE` from virtual values.
  Materialize virtual exit values to the stack first, then let entry trace loads
  reload normally.
- `regalloc_collect_next_uses` and `regalloc_maybe_free_snapshot` must not treat
  `REG_SUNK` entries as normal register/spill uses.
- The main IR emission switch must emit no code for `REG_SINK`/`REG_SUNK`
  recipe instructions.

## Side Trace Replay

Update `record_start_side` so parent snapshots can replay virtual values:

- If a parent snapshot entry is constant, keep existing behavior.
- If it references a normal parent IR value, keep existing `IR_PMOV` behavior.
- If it references parent `IR_ALLOC` with `reg == REG_SUNK`, recursively replay
  equivalent child IR:
  - child `IR_ALLOC`
  - child `IR_REF` for each relevant constant offset
  - child `IR_STORE` for each retained sunk store before the parent snapshot
- Parent field values that are normal IR values replay through `IR_PMOV`.
- Parent field values that are themselves `REG_SUNK` replay recursively.

This allows sinking through side traces. If the side trace never escapes the
object, its own `sink_allocs` pass can mark the replayed child allocation sunk
again. If the side trace reads a field, existing store-to-load forwarding should
see the replayed stores.

## Tests

Add focused Scheme tests for:

- cons allocation with immediate field reads and no escape
- allocation live only in a guard snapshot and materialized correctly on exit
- parent sunk allocation replayed into a side trace and unused there
- side trace reading a field from a parent-sunk allocation
- duplicate references to the same sunk object preserving `eq?` after exit
- nested sunk objects, e.g. a sunk cons field containing another sunk cons

Run:

```sh
cmake --build build
ctest --test-dir build -j
```

Use verbose IR printing while validating:

- print `REG_SINK` and `REG_SUNK` distinctly
- show which snapshot entries trigger unsinking
- optionally log stores selected by the unsink scan

## Initial Scope

- Sink `IR_ALLOC` only.
- Start with constant-size object allocations.
- Support normal object-field `IR_STORE` first.
- Add char/byte stores only after object-field sinking is correct.
- Do not change the snapshot data layout.

## Pseudocode

• opt_sink(trace):
    if trace has no IR_ALLOC:
      return

    // Mark values/allocations that must stay real.
    mark_snapshot_roots(trace.last_snapshot)
    mark_non_sinkable_uses(trace)

    // Anything still unmarked and eligible can be virtual.
    tag_sinkable_allocs_and_stores(trace)

  mark_snapshot_roots(snapshot):
    for entry in snapshot.slots:
      if entry.val is IR ref:
        mark(entry.val)

  mark_non_sinkable_uses(trace):
    // Walk backward so marks propagate through dependencies.
    for ir = trace.last_ir downto trace.first_ir:
      switch ir.op:

        case IR_LOAD:
        case IR_LOAD_CHAR:
        case IR_LOAD_BYTE:
          // If store-to-load forwarding did not remove the load,
          // the object must exist.
          mark(ir.op1)
          break

        case IR_STORE:
        case IR_STORE_CHAR:
        case IR_STORE_BYTE:
          alloc = allocation_reached_by_ref(ir.op1)

          if alloc does not exist:
            // Store target is not a known local allocation.
            mark(ir.op1)
          else if store offset/ref is not sinkable:
            // Dynamic or unhandled store address.
            mark(ir.op1)

          // The stored value must be kept alive if this store becomes
          // part of an unsink recipe.
          mark(ir.op2)
          break

        default:
          if ir is marked or ir is a guard/side-effect:
            mark(ir.op1 if IR ref)
            mark(ir.op2 if IR ref)
          break

  allocation_reached_by_ref(ref):
    if ref is constant:
      return none

    ref_ir = IR[ref]

    if ref_ir.op != IR_REF:
      return none

    if ref_ir.op2 is not constant:
      return none

    base = ref_ir.op1
    if base is constant:
      return none

    base_ir = IR[base]
    if base_ir.op != IR_ALLOC:
      return none

    return base

  tag_sinkable_allocs_and_stores(trace):
    for ir = trace.last_ir downto trace.first_ir:
      switch ir.op:

        case IR_ALLOC:
          if ir is eligible and not marked:
            ir.reg = REG_SINK
          else:
            clear_mark(ir)
          break

        case IR_REF:
          base = ir.op1
          if base is IR ref and IR[base].reg == REG_SINK:
            ir.reg = REG_SINK
          break

        case IR_STORE:
        case IR_STORE_CHAR:
        case IR_STORE_BYTE:
          alloc = allocation_reached_by_ref(ir.op1)

          if alloc exists and IR[alloc].reg == REG_SINK:
            ir.reg = REG_SINK
          break

        default:
          clear_mark(ir)
          break

  Then snapshot/backend handling later does the promotion:

  snapshot_needs_value(ref):
    ir = IR[ref]

    if ir.reg == REG_SINK && ir.op == IR_ALLOC:
      ir.reg = REG_SUNK
      recursively_mark_unsink_inputs(ref, snapshot.ir)

  recursively_mark_unsink_inputs(alloc_ref, limit_ir):
    alloc = IR[alloc_ref]

    if alloc.op1 is IR ref:
      mark_real_value(alloc.op1)  // dynamic size, if supported

    for each store before limit_ir:
      if store.reg != REG_SINK:
        continue
      if store belongs to alloc_ref:
        val = store.op2

        if val is IR_ALLOC with reg == REG_SINK:
          IR[val].reg = REG_SUNK
          recursively_mark_unsink_inputs(val, limit_ir)
        else if val is IR ref:
          mark_real_value(val)

  Simplified mental model:

  1. Mark everything that cannot be virtual.
  2. Unmarked eligible allocations become REG_SINK.
  3. Stores/refs into those allocations become REG_SINK recipe nodes.
  4. If a snapshot references a REG_SINK allocation, promote it to REG_SUNK.
  5. REG_SUNK values are rebuilt from REG_SINK stores on exit.
