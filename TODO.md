# working on

* put first couple args in regs (any sloads at top)

# TODO list

* chudnovsky /pi need bignum
* mbrotZ needs complex
* gcbench needs records
* equal needs cycle=
* bv2string needs bytevectors

# Bytecode generator / VM

* unary negation pass integration, i.e., integrate (- x)
* simplex has jmps to jmps? extra crap

## bytecode perf improvements 

* could put memq/assq/length/map/append/string-append etc as intrinsics
* faster call/cc - flush frames w/underflow handler.  Overflow handler can also just flush frames.

* remove hotspot for non-jit / new bytecode
* could do special branches for 'char=', '=', where we know it is a quick-branch, and know it fits in 16 bits
* could do special opcodes for true, false.  basically return 'konst'

* (letrec the bootstrap) / module-ify the bootstrap
* 'big' register moves / just get fftrad4 working, with a constant-ify pass
* we could be smarter about calls call callt: Order arguments such that min # of things are saved.  I.e. especially GGETs can be last.
 This probably has no effect on the VM, but might benefit the jit.
* can also optimize loop moves - i.e. last eval doesn't need to mov, some args don't need to mov.
* funcv/clfuncv could alloc all at once
* could do a return constant bytecode for empty list, true, false

## safety improvements
* TODO GSET check
* do better for destination driven code gen - 
   * return 'undefined' for value, but only for setters if rd is set.
* letrec check
* return accept args num 

* Go thorugh all of vm and check for safety!
* various check for const size overflow, reg or opcode overflow
* fuzz bytecode reader

## VM cleanup
* GC - up sz based expanding
* make a 'vm state' struct, so we can run multiple vm's?
* remove indirection for consts/bc
* comments in output

# JIT TODO:

* Figure out why jloop records fail in replay/asm_x64???
* figure out why non-looping ack fails with 1 trace
    * it's because we save the frame state for looping, 
	* but don't advance to next func/pc in last framestate.

* fix stack size adjust  
* and in replay is borken
  
* various JIT improvements
  * maybe put first X args in regs automatically for parent trace too?
  * maybe even type check them first?
  * save less in snap
  * closures can be exact in snap and constants
  * don't need to save func ptr slot for callt or ret if it's the same
  * use RAX for tmp instead of R15 - RAX has shorter ops for MOV, etc
  * Use shorter instruction sequences for small constants
  * we should be able to coalesce arg typechecks if they are the same.
  * Maybe a speical SLOAD EQ for RET instead, since we don't need to typecheck
  * Typechecks need a rethink - we can special case some stuff like eq?/eqv?, merge typechecks, etc.
  * load return slot only once somehow.  SLOAD -1, or RLOAD, or something.
      Only seems to matter for long strings of returns.  It should be in cache anyway, and we have to load
	  it at least once.
  
* merge record_run and jit_run exit stub
* All of 'RECORD' probably needs type tests when we access frame.

* BROKEN keeps jitting even on jfunc.  Should hotmap on func instead of call?
* fix snap saves for branches, don't merge with 0, bump one past.

* need to purge snap to minimum entries.

* do better recursion 
  * maybe flush traces (recursively) if we find a new up or down recursive trace
  * fib 39 re-jits tails, because downrec happens first.  Even luajit does this.  Unrolling probably helps.

* reg alloc - needs spilling.  
    Needs either backwards pass with inserts (for spills), or do it at the same time as backwards codegen
	Also, at calls/intrinics we need to know which caller-save regs to spill

# OPTS

* dce
* global fetches


