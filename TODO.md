## Release checklist

[x] fix (= 4.0 4)

[x] implement eq? hashtables
[x] use new hashtables in bc.scm, string->symbol, srfi 69, maybe symbol lookup in expander
  * ugh its broken if we use it in expander code..... so ugh
    * it's because SCM_GC_CNT isn't preserved across gc image and loading.  Doh.
   

[x] get macros solid - pass macro tests
[x] get r5rs_pitfalls working
[x] pass r5rs-tests

[ ] work on r7rs-tests
  * about halfway done
[ ] Get all the argtype stuff calling error instead
[ ] merge in the 'fast' VM branch?

[ ] cleanup record.c
[ ] cleanup vm.c


## JIT backlog

* record APPLY

* returning trace handling - currently we allow ANY poly trace to return,
  while old hawk didn't allow any until blacklist_max/2, then *any* trace could return

* lots of CCALL cleanup - regalloc, live register save/restore, etc

* cleanup RTMP / RTMP2 usage, it's unclear when there is overlap between backends and
  emit.c.  Maybe a reserve_tmp() with two temps?  At least that could abort() on runtime issues.
  
  We COULD reserve tmps in the register allocator, but initial tests
  don't show an extra free reg really helping on x64 (and we have so many more on aarch64).

* TYPECHECK does different things for flonum vs. GPRs. ugh.
  * flonums must be eagerly typechecked, since we need to know if we need FPR vs GPR
  * but everything else is lazy, since we don't want to typecheck
    things like IR_LOAD followed by IR_STORE of the same value! If we don't need to know it's type, don't typecheck.

* we could add a GC_ENSURE.  It wouldn't work for variably sizxed ALLOC, but it would save having to register save/restore for snapshots *at all*, and we could merge all fixed-size allocs to fastpaths!
  * basically split the *do we have enough memory?* path from the *bump the pointer and allocate* path

* we can do more register targetting of ending snapshot: we're always going here, if it is a side trace, we can target the orgiinal registers!

* we could keep boxed/unboxed flonum pairs around? we might be
  re-boxing in some cases instead of re-using the unchanged old box
  (only in cases of IR_STORE or taking a snapshot)
* currently we're flushing everyting live-across a CCALL to spill
  slot - we don't use callee saved.  The reason is to make it easy for
  gc to work across CCALL.  This assumes CCALLs are rare, maybe
  experiment with this if they're not.

# VM backlog

* track stack-top
* missing multi-value callcc returns I think?
* we store state VM, the only place it is used is to flush traces in the FOREIGN_CALL to dump image and die. ugh.
* LOOP could just do a memmov instead?

### Optimization passes

X fold 
   X cse
X mem opts (store/load, load/load)
* sinking
* loop
X dce

# notes:

* using a VM forces us to reserve stack space for args, unlike a compiler. For large stack usage this results in higher memory use.  See sum1.scm
* ^^ no that's not it, it's that we need to save stack space by choosing order of evaluation for function call arguments! constants don't need to be saved on the stack and can be materialized later.
