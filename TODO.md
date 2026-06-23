## Release checklist

Hawk2 improvements:
[ ] figure out why dynamic is so much slower than oldhawk
    * again compilation helps, so probably inling
	* NO NEED TO TYPECHECK for EQ/NE, eq? vs. EQV? in traces.  ugh
[ ] compiler.scm is slower
    * GC_ALLOC helps, but hurts other benchmarks
	* somehow compilation in chez helps - so it's likely tons of inlining
[ ] optimize recording EQ EQV NUMEQ based on type if one is constant.  Or typecheck 
     just one side, and if it's a non-heap or symbol, no need to typecheck the other side.
   [ ] move memq, memv, assq, assv back to scheme.  Our tracer is good enough, but we do need the opt above
[x] Figure out why pi and maze pycket tests fail in hawk
[x] Simplify regalloc
[x] Finish pycket analysis 
[x] ☄️Auto flvector 
   * missing fallback conversion
[x] ☄️ Make real port type
[x] Rc gc - probably no speed bump but will reduce memory usage by 3x
[x] IR ABC array bounds check
[x] Deopt in interpreter instead of code (required for alloc sinking)
[x] ☄️ Alloc sinking (after reverse regalloc) (tried and not helpful)
[ ] ☄️ Loop analysis, getting phis right is hard, based on current loopback algo. Phi all implicit stack load/stores based on snapshots, emit explicit loads, emit explicit type checks probably. Only do for offset =0. Then several loops / passes to remove unnecessary phis.  
     YES this definitely helps on shit like puzzle

[x] IR_ABC
[ ] ☄️ int range analysis for loops and add/sub/mul overflow (requires abc & loop opt)

[ ] Optimize vm - set/get type opcodes, builtins. Even farther - gcall, vn math and cmp ops

[ ] GC: missing lines, missing backup SATB cycle collector.  background thread for decrements?

[ ] Reify code generator tester!!!! So good. Generate ast. Choose a path. Generate symbolic and send to z3, then use z3 solution! To print a complete program. Can force a loop with at least X , so we can even ensure jit runs!
[x] Port over all the fold rules from luajit, pypy, dstrogov ir, or use z3 to prove new ones 

[x] Merge constants on traces, linear scan
[ ] When trace cache full, flush it automatically. 
[ ] Exe builder. 
[ ] Various trace interfaces, like dump image and flush trace cache
[ ] Fix (number?) Type rep to be tower of numbers like ports will be
[ ] Replace libffi with a tiny faster version, merge code with jit, map to (foreign c) interface
[ ] Luajit style double ended ir ins / constants???
[ ] Cleanup backends based on luajit. See chatgpt chat
[ ] Clean folding and memory optimizations in fold.c to use fold engine, same as luajit

[ ] Adding special math case-lambda type can remove need to inline bc at all
### Bugs:
[ ] Fixnummax/ -1 is probably broken. Div has two special cases. 
[ ] / 0 check aborts, not error

### other:

[ ] some github actions to test build for ubuntu, osx, arch? gcc, clang?
[ ] paper

## slow vs Chez

* fibc, ctak: we copy twice on continuations, so it is unsurprising ctak is 2x slower.
* compiler, dynamic - super branchy?  something else?
  * at least part of it is both have 1000+ traces, and at least dynamic 
    is showing walking traces as roots is somewhat slow.  traces I guess need to be part of GC
	and part of the RC space to make this faster.

Every other test is within noise.

## slow VM
For the VM specifically, we could speed up these, but it wouldn't really affect JIT.

* bytecode ops: string ref/set, vector ref/set, car/cdr, record ref/set
    * this will only speed up the VM, and nothing for JIT (since the jit is 
	  already able to inline through all these)
* IR_ABC for faster bounds checking, especially vectors
    * would improve array1, puzzle, triangl, but that's it.  Rolling
      the checks in to specific opcodes above would speed up VM
* convert to bytecode: assq, length, listp, equal, stringcopy
     * tested, didn't find perf improvement in JIT, but would speed up VM
	 


# Known bugs

[ ] r7rs-tests LOOKUPs are too long & overflowing because main is too long. 
    Extend to 32-bit LOOKUP/CONST/DEFINE.  Also add checks for JMP and IF, make sure
	they don't exceed distance
	We check for overflow, but the main issue still exists.	
	Probably also need to check all the JMP cases. 
	In fact, the whole thing needs a rewrite for JMP using labels, and a separate pass
	to reduce WIDE opcodes or something.
	
# Missing features

Would be super nice to have:

* set (features) via command line
* add library paths via command line
* add an --exe option to build a new image and link it (static or dynamic), so we get a real exe
* a --dump flag to list compiled bytecode without actually running
* in fact a whole 'hawk' library with options to control the expander, dump bitcode, dump traces, reset traces, 
  save-image-and-die, etc etc.  These can all be pieced together for testing but not implemented yet as reusable library.

## JIT backlog

* we cold fold more EQ NEQ ops - case in particular does a lot of NEQ in a row, followed by a single EQ
  * or lower case more effectively somehow?

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

* use destination-driven as in previous??
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
