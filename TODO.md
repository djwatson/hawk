# Getting all jit to work bench2

* looping shit in destruc
* gcbench

# Recorder

* sum1 - integer->char, islte, peek, inexact
* read1 - char cmp, peek, callcc, make-string, integer->char, 
* diviter - loops
* wc - list funcv
* string - funcv, make-string loops
* fibc/ctak - callcc
* tail - read-line
* nqueens - ????
* cpstak??
* takl?
* primes - loops. apply, values clfuncv
* deriv - list, values
* triangl-?
* destruc - loops 
* mperm-???
* gcbench - loop
* puzzle - loops, call/cc
* paraffins - ???? loops 
* mazefun - list, mulvv random gen, loops, ???? UNROLL IMIT
* simplex - mulvv, loops, flaots
* lattice - apply, loops, ????, NEEDS better closure analysis
* browse - loops, integer->char, string->symbol, make-string, 
* graphs - loops???? --- closure sinking
* conform - loops???????? vector funcv, string-append, make-string
* maze - loops???????????? mulvv
* earley - ??????????????, make-vector
* peval - ????????? list, apply, make-string
* boyer, nboyer - ???????????????????????
* matrix - mulvv, make-vector, apply, 
* dynamic - islte, char cmp, peek, callcc
* slatex - peek, make-string, char cmp
* compiler- char-cmp, string->symbol, make-string, integer->char, isgt, apply, 


* clfunc / clfuncv
  * array1
  * tail
  * nqueens
  * deriv
  * peval
  * slatex
  
* make-vector
  *array1
* apply 
  * primes
* mulvv
  * maze

* make-vector
  * graphs
* make-string
  * browse
  * conform
  
* string->symbol
  * browse

* integer->char
  *browse
* symbol->string
  *browse
  
* funcv
  * deriv for list
  * values
  * mzefun
  * peval
  * conform - vector, string-append
* callcc / callcc-resume
  * fibc
  * ctak
  * puzzle
* inexact
  * mbrot
* flonums
  * sumfp
  * fibfp
  * mbrot
  * quicksort
OK
* sum
* fib
* ack
* tak
* ntakl
* takl
* cpstak
* divrec
* diviter
* wc
* cat
* mperm

????
* graphs
* earley

* nboyer needs longer traces and larger blacklist

# working on

* extend max trace size and fix bugs

* 'closure' opcode should all be in the bcfunc prototype, and done behind a single opcode.
  * Do something to get rid of zero-initializing??
  * cleanup the second arg, can be inline instead of separate number
* polymorphic / non polymorphic
* CALLXS betterness
  * can reg hint anthing that covers a call

* LOAD use for car/cdr, AND vec.
* fuse
* check sload type for VEC
* add typecheck in LOAD
* ABC
* cleanup record for JISTE/JISLT, etc

* UNBOX can delay typecheck

* Check for all consts in asm_x64 are reloc'd
* GC is causing additional traces?? ugh

* typecheck/no typecheck - we can drop typecheck if it is unused
  * BUT jguard counts as a use!!!
  * similar to ARG - we don't have to typecheck ARG if unused
* stack expand:cleanup

* closure-get, and in fact all calls, must be same closure.
* cleanup snap guards for jisf, etc
* folding GGET: put in emit somewhere, check for GSET
* Merge parent SLOADS if they are the same value.
* make make notes where ARG vs SLOAD
* better closure analysis for empty closure var
* SLOADS need a parent bit in OP2 instead of checking for guard
* ARGS on jit_entry need typecheck (and should already be checked on loop?)

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

* tail calls still do a mov/return for let().  see cat.scm

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

* and in replay is borken
  
* various JIT improvements
  * 'loop' can know exact arguments in regs?  Or just not loopify at all?
  * save less in snap - dead elimination, read-only
  * closures can be exact in snap and constants
  * use RAX for tmp instead of R15 - RAX has shorter ops for MOV, etc
  * we should be able to coalesce arg typechecks if they are the same.
  * Maybe a speical SLOAD EQ for RET instead, since we don't need to typecheck
  * Typechecks need a rethink - we can special case some stuff like eq?/eqv?, merge typechecks, etc.
  * load return slot only once somehow.  SLOAD -1, or RLOAD, or something.
      Only seems to matter for long strings of returns.  It should be in cache anyway, and we have to load
	  it at least once.
  * GC needs a rethink for jit. GGET/GSET/KONST only I think? KFUNC?
  * something something about GGET checks for func calls carried in snaps?
  
* merge record_run and jit_run exit stub
* All of 'RECORD' probably needs type tests when we access frame.

* need to purge snap to minimum entries. - kinda done, maybe a 'readonly' slot.  ONLY for sload, not ARG.

* do better recursion 
  * maybe flush traces (recursively) if we find a new up or down recursive trace
  * fib 39 re-jits tails, because downrec happens first.  Even luajit does this.  Unrolling probably helps.

* reg alloc - needs spilling.  
	Also, at calls/intrinics we need to know which caller-save regs to spill

# OPTS

* dce
* global fetches


