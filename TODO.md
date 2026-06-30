## Release checklist

* some github actions to test build for ubuntu, osx, arch? gcc, clang?
* paper

## slow vs Chez

* figure out why dynamic is so much slower than oldhawk
    * again compilation helps, so probably inlining
	* assv in C vs scheme?
	* NO NEED TO TYPECHECK for EQ/NE, eq? vs. EQV? in traces.  ugh
	* 50MB nursery vs 32mb
* compiler.scm is slower
    * GC_ALLOC helps, but hurts other benchmarks
	* somehow compilation in chez helps - so it's likely tons of inlining
* fibc, ctak: we copy twice on continuations, so it is unsurprising that ctak is 2x slower.

Every other test is within noise.

## slow VM
For the VM specifically, we could speed up these, but it wouldn't really affect JIT.

* bytecode ops: string ref/set, vector ref/set, car/cdr, record ref/set
    * this will only speed up the VM, and nothing for JIT (since the jit is 
	  already able to inline through all these)
* convert to bytecode: assq, length, listp, equal, stringcopy
     * tested, didn't find perf improvement in JIT, but would speed up VM
* optimize recording EQ EQV NUMEQ based on type if one is constant.  Or typecheck 
     just one side, and if it's a non-heap or symbol, no need to typecheck the other side.
   * move memq, memv, assq, assv back to scheme.  Our tracer is good enough, but we do need the opt above
	 
# Known issues

* r7rs-tests LOOKUPs are too long & overflowing because main is too long. 
    Extend to 32-bit LOOKUP/CONST/DEFINE.  Also add checks for JMP and IF, make sure
	they don't exceed distance
	We check for overflow, but the main issue still exists.	
	Probably also need to check all the JMP cases. 
	In fact, the whole thing needs a rewrite for JMP using labels, and a separate pass
	to reduce WIDE opcodes or something.
	
* Auto flvector 
   * missing fallback conversion. Watch out for GC issues, probably need special gc_log.

# Missing features

Would be super nice to have:

* set (features) via command line
* add library paths via command line
* add an --exe option to build a new image and link it (static or dynamic), so we get a real exe
* a --dump flag to list compiled bytecode without actually running
* in fact a whole 'hawk' library with options to control the expander, dump bitcode, dump traces, reset traces, 
  save-image-and-die, etc etc.  These can all be pieced together for testing but not implemented yet as reusable library.
* When trace cache full, flush it automatically. 
* Various trace interfaces, like dump image and flush trace cache

## JIT backlog

* fold.c: Clean folding and memory optimizations in fold.c to use fold engine, same as luajit

* backends could be cleaned up similar to luajit

* Luajit style double ended ir ins / constants???

* we cold fold more EQ NEQ ops - case in particular does a lot of NEQ in a row, followed by a single EQ
  * or lower case more effectively somehow?

* int range analysis for loops and add/sub/mul overflow (requires abc & loop opt)

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

* we could add a GC_ENSURE.  It wouldn't work for variably sized ALLOC, but it would save having to register save/restore for snapshots *at all*, and we could merge all fixed-size allocs to fastpaths!
  * basically split the *do we have enough memory?* path from the *bump the pointer and allocate* path

* we can do more register targetting of ending snapshot: we're always going here, if it is a side trace, we can target the original registers!

* we could keep boxed/unboxed flonum pairs around? we might be
  re-boxing in some cases instead of re-using the unchanged old box
  (only in cases of IR_STORE or taking a snapshot)
* currently we're flushing everyting live-across a CCALL to spill
  slot - we don't use callee saved.  The reason is to make it easy for
  gc to work across CCALL.  This assumes CCALLs are rare, maybe
  experiment with this if they're not.
  
* add some point the ir struct was expanded to support more than >256
  spill slots, this is probably unnecessary.
  
* better stack-top tracking: I tried and didn't find much improvment
* allocation sinking: I tried and didn't find much improvment.  Only happened in small side traces
* opt_loop: Tried it, it only really saw a huge win in puzzle: where an inner loop has repeated SLOADS.
            we could do a static pre-pass to improve this.

# VM backlog

* Fix (number?) Type rep to be tower of numbers like ports will be
* Adding special math case-lambda type can remove need to inline bc at all
* use destination-driven as in previous??
* track stack-top
* missing multi-value callcc returns I think?
* we store state VM, the only place it is used is to flush traces in the FOREIGN_CALL to dump image and die. ugh.
* LOOP could just do a memmove instead?

* unicode support is unimplemented.

* there's a VM only sampling profiler in git commit f4ba0ff, maybe port it and make it permanent?

* bigint could have faster fastpath for div, number->string, etc

# GC improvements:

* Add lines to blocks
* fix large object cycle collector - currently freeing large objects
  can make SATB walk walk to invalid mem.
  (gc_blocks are ok since they are never freed).
  
# notes:

* using a VM forces us to reserve stack space for args, unlike a compiler. For large stack usage this results in higher memory use.  See sum1.scm
* ^^ no that's not it, it's that we need to save stack space by choosing order of evaluation for function call arguments! constants don't need to be saved on the stack and can be materialized later.
