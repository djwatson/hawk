# Currently working on:

## tests:

* get r5rs scm working
   * mostly works, reader/ports need to get working.
* simplex is slower??? bad tracing

* ugh need to put back faster VM - things like browse too slow.
  * this is just inlining stuff I think.

* probably need to fix closure conversion at some point

* ugh typechecking - currently IR_PMOV and IR_ARG need auto-update types?
  lazy typechecking makes this tough??? maybe we just need to set it for IR_PMOV, NOT copying the previous type?

## JIT impl

* figure out why deriv is slow
  * heurstics can't catch single-looping trace
  * downrec abort not working (start of trace is failing?)
  * GC next_collect is 10x too big.
  * deriv.scm needs better closure conversion.

* downrec traces don't ensure_args_match and link without boxing/typecheck

* regalloc could be improved to not reserve RTMP2 ugh
  LOAD: could use IR_REF to remove RTMP2 usage
  STORE: could alloc a reg in IR_REF to 
  GSET: needs a tmp reg
  SLOAD: would need separate IR_TYPECHECK or tmp reg
  
* We can probably push RSTATE on the stack instead of keeping a register.

* currently (cons) calls IR_STORE, but this forces a snapshot-  many more snapshots than really necessary (because we're only storing to NEW memory, we shouldn't need to snapshot).

# VM impl

* track stack-top
* half finished - all the typcheck types - (need more ptr types)
* rest of ops: callcc/callcc_resume. That's it.
* update stack overflow, just allocate a new section (linked stack segments, much faster callcc handling)
* math and cmp ops have lots of spills in generated code.

# cleanup
* we can do more register targetting of ending snapshot: we're always going here, if it is a side trace, we can target the orgiinal registers!
* need a 'box' type so assignment-conversion doesn't need to set more than one thing
* be careful around vector init, ugh.
* Probably faster to just AND-align8 all allocs instead of requiring ALLOC to be sz aligned already.

# scheme cleanup
* builders needs to be in with the rest of the IR passes. Use builders instead of backtick to build stuff.
* matchers kinda suck with annotations and unused fields, ugh???
* move passes to separate file?

# simple VM

* debug info serialized - hmm maybe keep in scheme format?
* Hmmm maybe allow toplevel and module - DON'T inline modules?  Or track which are inlined? ugh.
  * make this optional, I guess.
* Ugh, same with ARG: we can't know to drop it. Don't know if unused based on only trace, need
  usage info from .... something? either a post-pass live in JIT from BC, or pre-pass in compiler.

## tracer
* dead/kills - no idea.  We could analyze bytecode, or just do
  top-of-stack tracking like previous.
* multiple return values from the start
* punt on: more than 256 refs.
* Do check for side-trace tail-call should be root loop abort
   * have code, need to see if useful on more tests
* we could keep boxed/unboxed flonum pairs around? we might be
  re-boxing in some cases instead of re-using the unchanged old box
  (only in cases of IR_STORE or taking a snapshot)

### opts

X fold 
   * gvn
* mem opts
* sinking
* loop? never really found useful, because reg-args covers most cases.
X dce - implicit.  Only useful with LOOP

# passes
* loops
* count uses 
* advanced closure conversion (with subpasses)

# notes:

* using a VM forces us to reserve stack space for args, unlike a compiler. For large stack usage this results in higher memory use.  See sum1.scm
* ^^ no that's not it, it's that we need to save stack space by choosing order of evaluation for function call arguments! constants don't need to be saved on the stack and can be materialized later.
