# Known bugs

[ ] r7rs-tests LOOKUPs are too long & overflowing because main is too long. 
    Extend to 32-bit LOOKUP/CONST/DEFINE.  Also add checks for JMP and IF, make sure
	they don't exceed distance
	We check for overflow, but the main issue still exists.	
	Probably also need to check all the JMP cases. 
	In fact, the whole thing needs a rewrite for JMP using labels, and a separate pass
	to reduce WIDE opcodes or something.

## Release checklist

[x] paper
[x] website
[x] benchmark numbers vs chez, x64 & aarch64, maybe VM.

[x] package for release
[ ] some github actions to test build for ubuntu, osx, arch? gcc, clang?

[ ] other tests like port tests, looping tests, copyish, division from callcc

## Perf fixes 

[ ] CLOSURE GET doesn't need typecheck EXCEPT for getting bcfunc ptr, 
    so make that a separate opcode.
[ ] bytecode ops: string ref/set, vector ref/set, car/cdr, record ref/set
[ ] IR_ABC for faster bounds checking, especially vectors
[ ] convert to bytecode: assq, length, listp, equal, stringcopy


# Missing features

Would be super nice to have:

* set (features) via command line
* add library paths via command line
* add an --exe option to build a new image and link it (static or dynamic), so we get a real exe
* a --dump flag to list compiled bytecode without actually running
* in fact a whole 'hawk' library with options to control the expander, dump bitcode, dump traces, reset traces, 
  save-image-and-die, etc etc.  These can all be pieced together for testing but not implemented yet as reusable library.

## JIT backlog

* record APPLY (currently we have fastpaths up to 8 length)

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
  
* add some point the ir struct was expanded to support more than >256
  spill slots, this is probably unnecessary.

# VM backlog

* track stack-top
* missing multi-value callcc returns I think?
* we store state VM, the only place it is used is to flush traces in the FOREIGN_CALL to dump image and die. ugh.
* LOOP could just do a memmov instead?

* unicode support is unimplemented.

* there's a VM only sampling profiler in git commit f4ba0ff, maybe port it and make it permanent?

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
