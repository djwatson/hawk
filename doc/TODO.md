# Getting all jit to work bench2

* loosing at: 
  * input/output buffering: wc, cat, dynamic
  * read: dynamic read1 sum1
  * call/cc: ctak, fibc
  * string ops: string
  * lattice: mostly catching the inner nested loop (lex-fixed) as a loop, and not allocating a closure for it.
    Need to inline called-once functions??
  * dynamic: read is super slow, read by char
  * graphs: LOOP_opt, sccp, GC
  * ?? peval - sccp
  * puzzle - optimistic globals / loop_opt
  
  * conform, nboyer, sboyer, graphs, 

# TODO
* fix letrec closures
  [x] new closure algo
  [ ] constant pointer-only closures
  [ ] optimistic monomorphic
* fusion - cleanup
  *vec, all
* string ops
* fix buffering
* optimistic monomorphic closures?

* lazier typechecking 
  * jguard counts as a use!
  * Free except VECTOR and maybe STRING type? ^
  * Necessary for dce of unused refs ^
* sccp pass / fold - 
  * Only matters for memory refs if we can CSE or DCE away^

* TRACE loop recording - 
  * CALLT should also detect loops, and flush original trace??
  
* UNDEFINED_TAG
* const pool
* cleanup register allocation - two-arg can be optimized

* LOOP_opt 
  * globals / loads only once ^
* gvn / dce 
  * unused loads ^ 

* NYI:apply, close, file-exists?, open, delete-file, read-line
* enregister return arg??
* allocation sinking for cons/closure/vector ^^
* reg hints across calls? and returns? ^^
  * CALLXS betterness
* RET implementation could actually RET? faster somehow?

* Better GC.
  * GC doesn't need to jump out of trace for most things?
  * merge GC checks?
  * full trace again

# working on

* records
* Merge parent SLOADS if they are the same value.
* SLOADS need a parent bit in OP2 instead of checking for guard

# TODO list

* chudnovsky /pi need bignum
* mbrotZ needs complex
* gcbench needs records

# Bytecode generator / VM

* unary negation pass integration, i.e., integrate (- x)
* simplex has jmps to jmps? extra crap

## bytecode perf improvements 

* tail calls still do a mov/return for let().  see cat.scm

* could put append/string-append/substring etc as intrinsics
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

* various check for const size overflow, reg or opcode overflow

## VM cleanup
* make a 'vm state' struct, so we can run multiple vm's?
* remove indirection for consts/bc
* comments in output

# JIT TODO:

* various JIT improvements
  * we should be able to coalesce arg typechecks if they are the same.
  * Maybe a speical SLOAD EQ for RET instead, since we don't need to typecheck
  * load return slot only once somehow.  SLOAD -1, or RLOAD, or something.
      Only seems to matter for long strings of returns.  It should be in cache anyway, and we have to load
	  it at least once.

* All of 'RECORD' probably needs type tests when we access frame.

* trace exits could patch all exit jumps directly instead of the exit branch.
  * also the exit branch still does a mov to R15
* Merge stubs like in luajit?

# OPTS

* gvn
* dce
* global fetches
* mem - L2L + S2L, DSE, AA
* sink
* loop
* constant folding / sccp
