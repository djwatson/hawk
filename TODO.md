# Known bugs

* bug save-and-die WHILE in a trace fails - because currently vm_trace_reset is lazy

TRACING - fix APPLY, that's whats causing compiler slowness

# Release checklist

[x] Closure conversion from O(0) closure paper 
   DONE! needs cleanup. remove old closure, simplify find free, make the constant/alias pass separate.
[x] values / call-with-values / multi-value returns in opcodes!
   [ ] fix call/cc multi-value returns
[x] Loops 
   [x] loop tracing.
   [ ]  more optimization of tracing interaction??
[ ] remove custom hashtable after we have a real eq? hashtable
[ ] Record every OPcode:
  * APPLY (+ the resulting call FUNC or IFUNC)
    * I didn't do this, but extended APPLY fastpath to length 8, and it never hits sys:APPLY in any benchmark now
	* I tried doing it, but it means 'argcnt' is no longer constant in snapshots, which is a pain.
	  We would have to length check BEFORE doing APPLY, which is ok I guess.  Never got it completely working
  [X] CALLCC & CALLCCRESUME
  * boxing in FFI
[x] Better inlining of existing, like change 3+ args to binops for +,-, etc
[ ] Inline a bunch of VM primitives to opcodes to make things faster
  * CONS, CAR, CDR
  * VECTOR MAKE_VECTOR VECTOR_REF VECTOR_SET VECTOR_LENGTH
  * STRING_LENGTH STRING_REF MAKE_STRING
  [x] MEMQ ASSV ASSQ
  * GCALL GCALLT (global call)
  * Math ops like ROUND SIN SQRT ATAN COS TRUNCATE FLOOR CEILING EXP LOG TAN ASIN ACOS
  
  * The JIT could dro pthe box_closure_flonum pass if we have
    * RATNUM, COMPNUM, CONS, since it could auto-convert the inputs.
  
Optional: 
[ ] GC old generation
[ ] flvector
[ ] opt_loop pass
[x] CSE
[ ] sinking to snaps

## JIT impl

* lots of ccall cleanup - regalloc, live register save/restore, etc

* cleanup new recording infra
* cleanup tmp /tmp2 reg shit.  it's getting sloppy

* figure out why deriv is slow
  * heurstics can't catch single-looping trace
  * downrec abort not working (start of trace is failing?)
  * GC next_collect is 10x too big.
  * deriv.scm needs better closure conversion.
  * It's because APPLY doesn't record doh :(

* downrec traces don't ensure_args_match and link without boxing/typecheck

* regalloc could be improved to not reserve RTMP2 ugh
  LOAD: could use IR_REF to remove RTMP2 usage
  STORE: could alloc a reg in IR_REF to 
  GSET: needs a tmp reg
  SLOAD: would need separate IR_TYPECHECK or tmp reg

* We could drop LRU, and just keep a list of last-used for EVERY op, probably cheaper.
  
* We can probably push RSTATE on the stack instead of keeping a register.

* Currently to patch up IR_TYPECHECK we do a forward scan from IR_ARG, 
  but that's silly, we can just check when we emit if the parent IR_ARG or IR_PMOV needs it
  when processing IR_TYPECHECK

* currently (cons) calls IR_STORE, but this forces a snapshot-  many more snapshots than really necessary (because we're only storing to NEW memory, we shouldn't need to snapshot).

* we could add a GC_ENSURE.  It wouldn't work for variably sizxed ALLOC, but it would save having to register save/restore for snapshots *at all*, and we could merge all fixed-size allocs to fastpaths!
  * basically split the *do we have enough memory?* path from the *bump the pointer and allocate* path

# VM impl

* track stack-top

# cleanup
* LOOP could just do a memmov instead?
* we store state VM, the only place it is used is to flush traces in the FOREIGN_CALL to dump image and die. ugh.
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
   * cse
* mem opts
* sinking
* loop
X dce - implicit.  Only useful with LOOP

# notes:

* using a VM forces us to reserve stack space for args, unlike a compiler. For large stack usage this results in higher memory use.  See sum1.scm
* ^^ no that's not it, it's that we need to save stack space by choosing order of evaluation for function call arguments! constants don't need to be saved on the stack and can be materialized later.
