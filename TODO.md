# TODO list

* chudnovsky /pi need bignum
* mbrotZ needs complex
* gcbench needs records
* equal needs cycle=
* bv2string needs bytevectors

# Bytecode generator / VM

## bytecode perf improvements 

* browse - fold immeidate guard/NULL? 
* cat - case-lambda, guard/jmp folding
* conform - all in memq.  fold null?
* cpstak - clopsure-ptr CALL opt, probably nothing else.
* ctak - improve CALLCC 
* deriv - map2 is slow. ALso calls list a lot, split func funcv.  Only GC once for varargs if possible?
* destruc - length is slow.  Consider adding as bytecode
* diviter, divrec - guard check branch merge.
* dynamic - callcc, assv, memv,(probably all fixed by branch rollup) peek - case-lambda
* earley - good. 
* fft - good
* fibc - callcc&resume.  Zero.
* fibfp - good.  Better GC.  Somehow tell math funcs they can reuse one arg?  Or probably just leave to JIT.
* fib - good.
* gcbench - good
* graphs - only lambda-lifting would solve.
* lattice - foey.  Better closure analysis. null? inline. Probably inlining generally.
* matrix - branch folding but probably not much else.
* mazefun - recognize (= i 0) as (zero? i)
* maze - guard folding for fixnum
* mbrot - ok
* mperm - fold zero?
* nboyer - branch folding NULL?.  all GC. 
* nqueens - jmp inlining, fold null?

* ret a const?
* case-lambda!
* funcv new bytecode
* closure calls as a new bytecode instr
* remove hotspot for non-jit / new bytecode
* letrec the bootstrap
* $zero? or inline zero
* FLIP branches when emitting jmps if possible.
* empty branches can return new destination?? probably uncommon.
* need IF NULL, IF NOT NULL checks.  SUper common.
* For branches we can immediately run the following jump if possible?  single branch instead of indirect.
* 'big' register moves
* we could be smarter about calls call callt: Order arguments such that min # of things are saved.  I.e. especially GGETs can be last.
 This probably has no effect on the VM, but might benefit the jit.
* could add sume 'VN' variations of < >, EQ, etc
* BIGREGS - fix fftrad4
* faster call/cc - flush frames w/underflow handler.  Overflow handler can also just flush frames.

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
* Figure out why JFUNC immediate records fail - we should start recording on JFUNC and not CALL
* Figure out why jloop records fail in replay/asm_x64
* figure out why non-looping ack fails with 1 trace
    * it's because we save the frame state for looping, 
	* but don't advance to next func/pc in last framestate.

  * fix stack size adjust  
  * and in replay is borken
  
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
  
  * exit stubs can be much smaller
  * get exit trace from PC?????

* merge record_run and jit_run exit stub
* All of 'RECORD' probably needs type tests when we access frame.

* CALL neesd to load args too??

* BROKEN - fix traec num, store in D, max traces cache
* BROKEN keeps jitting even on jfunc.  Should hotmap on func instead of call?
* fix snap saves for branches, don't merge with 0, bump one past.

* need to purge snap to minimum entries.

* do better recursion 
  * maybe flush traces (recursively) if we find a new up or down recursive trace
  * fib 39 re-jits tails, because downrec happens first.  Even luajit does this.  Unrolling probably helps.

* reg alloc - needs spilling

# OPTS

* simple loop op
* dce
* global fetches


