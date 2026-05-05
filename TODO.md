# Known bugs

* bug save-and-die WHILE in a trace fails - because currently vm_trace_reset is lazy

# Release checklist

[ ] array bounds checking
  
## JIT impl

* record APPLY

* downrec handling - currently this ONLY starts based on side exits, so for example test/sum1.scm never traces
  a downrec, resulting in HUGE vm time.

* lots of ccall cleanup - regalloc, live register save/restore, etc

* cleanup new recording infra
* cleanup tmp /tmp2 reg shit.  it's getting sloppy

* TYPECHECK does different things for flonum vs. GPRs. ugh.
  * flonums must be eagerly typechecked, since we need to know if we need FPR vs GPR

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


* we could add a GC_ENSURE.  It wouldn't work for variably sizxed ALLOC, but it would save having to register save/restore for snapshots *at all*, and we could merge all fixed-size allocs to fastpaths!
  * basically split the *do we have enough memory?* path from the *bump the pointer and allocate* path

# VM impl

* track stack-top
* remove weird custom hashtable, because we're missing eq? support
* missing multi-value callcc returns I think?

# cleanup
* LOOP could just do a memmov instead?
* we store state VM, the only place it is used is to flush traces in the FOREIGN_CALL to dump image and die. ugh.
* we can do more register targetting of ending snapshot: we're always going here, if it is a side trace, we can target the orgiinal registers!
* need a 'box' type so assignment-conversion doesn't need to set more than one thing

# simple VM

* debug info serialized - hmm maybe keep in scheme format?
* Hmmm maybe allow toplevel and module - DON'T inline modules?  Or track which are inlined? ugh.
  * make this optional, I guess.
* Ugh, same with ARG: we can't know to drop it. Don't know if unused based on only trace, need
  usage info from .... something? either a post-pass live in JIT from BC, or pre-pass in compiler.

## tracer
* dead/kills - no idea.  We could analyze bytecode, or just do
  top-of-stack tracking like previous.
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
X mem opts (store/load, load/load)
* sinking
* loop
X dce - implicit.  Only useful with LOOP

# notes:

* using a VM forces us to reserve stack space for args, unlike a compiler. For large stack usage this results in higher memory use.  See sum1.scm
* ^^ no that's not it, it's that we need to save stack space by choosing order of evaluation for function call arguments! constants don't need to be saved on the stack and can be materialized later.
