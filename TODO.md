# Currently working on:

## tests:

* get tests running again: exact, FFI for string returns? printing flonums
* simplex is slower??? bad tracing

* ugh need to put back faster VM - things like browse too slow.
  * this is just inlining stuff I think.

* probably need to fix closure conversion at some point

## broken bench2:
* tail: read-line
* chudnovsky, pi: bignum
* compiler: various bugs
* ctak, fibc, maze, puzzle: call/cc
* dynamic: ???
* fibfp: incorrect result - "read"ing
* matrix?? hangs
* equal - need equal with loop checking
* mbrotZ: imaginary
* scheme: caaar
* cat, ray, read1, sum1, slatex: input/output needs buffering, too slow to finish.


## JIT impl

* lots of ccall cleanup - regalloc, live register save/restore, etc

* cleanup tmp /tmp2 reg shit.  it's getting sloppy

* need to memset(0) records I think? ugh.

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

* Currently to patch up IR_TYPECHECK we do a forward scan from IR_ARG, 
  but that's silly, we can just check when we emit if the parent IR_ARG or IR_PMOV needs it
  when processing IR_TYPECHECK

* currently (cons) calls IR_STORE, but this forces a snapshot-  many more snapshots than really necessary (because we're only storing to NEW memory, we shouldn't need to snapshot).

* we could add a GC_ENSURE.  It wouldn't work for variably sizxed ALLOC, but it would save having to register save/restore for snapshots *at all*, and we could merge all fixed-size allocs to fastpaths!
  * basically split the *do we have enough memory?* path from the *bump the pointer and allocate* path

# VM impl

* track stack-top
* rest of ops: callcc/callcc_resume. That's it.
* update stack overflow, just allocate a new section (linked stack segments, much faster callcc handling)
* math and cmp ops have lots of spills in generated code.???

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
* currently we're flushing everyting live-across a CCALL to spill
  slot - we don't use callee saved.  The reason is to make it easy for
  gc to work across CCALL.  This assumes CCALLs are rare, maybe
  experiment with this if they're not.

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
