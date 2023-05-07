# TODO list

* figure out why non-looping ack fails with 1 trace
    * it's because we save the frame state for looping, 
	* but don't advance to next func/pc in last framestate.
* JIT todo:
  * fix stack size adjust  
  
* various JIT improvements
  * fix branching jumps to jump one past.
  * don't save/restore snap to stack between parent and side trace, reuse regs
  * maybe put first X args in regs automatically for parent trace too?
  * maybe even type check them first?
  * save less in snap
  * closures can be exact in snap and constants
  * don't need to save func ptr slot for callt or ret if it's the same
  * use RAX for tmp instead of R15 - RAX has shorter ops for MOV, etc
  * don't adjust RDI if it hasn't changed
  * don't bother to save RDI until C code exit sequence
  * Use shorter instruction sequences for small constants
  * move side exit code to C instead of generated (but need both to gen for side or loop exits)
  * mv push/pop sequence to separate stub func
  * --joff is whacky, probably need to write asm.  sigh.
     * looks like it got worse after adding asmjit/capstone.
	 * because of memcpy's and record() and jit and shit aren't outlined like they should be.
	 * Maybe because of global vars? dunno.
  * we should be able to coalesce arg typechecks if they are the same.
  * Maybe a speical SLOAD EQ for RET instead, since we don't need to typecheck
  * Typechecks need a rethink - we can special case some stuff like eq?/eqv?, merge typechecks, etc.

* merge record_run and jit_run exit stub
* All of 'RECORD' probably needs type tests when we access frame.

* CALL neesd to load args too??

* BROKEN - fix traec num, store in D, max traces cache
* BROKEN keeps jitting even on jfunc.  Should hotmap on func instead of call?
* fix snap saves for branches, don't merge with 0, bump one past.

* need to purge snap to minimum entries.

* do better recursion 
  * maybe start traces on RET?
  * maybe flush traces (recursively) if we find a new up or down recursive trace
  * fib 39 re-jits tails, because downrec happens first.  Even luajit does this.  Unrolling probably helps.

* reg alloc - needs spilling
* fixup all opcodes of 'D' type
* various check for const size overflow, reg or opcode overflow
* fuzz bytecode reader
* remove indirection for consts/bc
* Add define tags/header for runtime types

# OPTS

* simple loop op
* dce
* global fetches


# Bytecode generator

## PERF
* we could be smarter about calls call callt: Order arguments such that min # of things are saved.  I.e. especially GGETs can be last.

## CLEANUP
* cleanup bytecode ops order
* split bc to separate files
* Double check 'VN' use D reg

## TODO
* comments in output
* name more lambdas, define, let
*could add sume 'VN' variations of < >, EQ, etc


* lets shouldn't be modified by alexpander, but get let loop working (let-internal?)
* rest params
* assignment conversion
* closure conversion
* fix letrec
* tail call register alloc?

