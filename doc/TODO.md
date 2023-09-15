# Getting all jit to work bench2

* heissen bug in bench2/compiler.scm.bc

* multiple traces???
  * fix multiple trace check for jfunc, up/downrec, jloop to find correct alternate trace

* TOo much VM time - fib (fail to catch uprec), earley (uneoll), scheme(unroll?), slatex (missing funcs) lattice?(unroll)

* apply

# TODO

* NYI:apply, close, file-exists?, open, delete-file, read-line

* optimistic global calls - needs frontend change, MAYBE just all optimistic globals
  and backend optimization / clearing of traces.
* sccp pass / fold
* singleton functions /closures
* lazier typechecking
* TRACE loop recording - 
  * need unroll check for CALLT.  
  * CALLT should also detect loops, and flush original trace
  * downrec could flush original trace if not uprec?
  * test with fib39
* UNDEFINED_TAG
* fusion
* const pool
* cleanup register allocation - two-arg can be optimized

* enregister return arg??
* better closure allocation in frontend - full closure optimization
* allocation sinking for cons/closure/vector
* reg hints across calls? and returns?
* RET implementation could actually RET? faster somehow?

# working on

* 'closure' opcode should all be in the bcfunc prototype, and done behind a single opcode.
  * Do something to get rid of zero-initializing??
  * cleanup the second arg, can be inline instead of separate number
* polymorphic / non polymorphic
* CALLXS betterness
  * can reg hint anthing that covers a call

* typecheck/no typecheck - we can drop typecheck if it is unused
  * BUT jguard counts as a use!!!
  * similar to ARG - we don't have to typecheck ARG if unused
* stack expand:cleanup

* records
* folding GGET: put in emit somewhere, check for GSET
* Merge parent SLOADS if they are the same value.
* make make notes where ARG vs SLOAD
* SLOADS need a parent bit in OP2 instead of checking for guard
* ARGS on jit_entry need typecheck (and should already be checked on loop?)

# TODO list

* chudnovsky /pi need bignum
* mbrotZ needs complex
* gcbench needs records

# Bytecode generator / VM

* unary negation pass integration, i.e., integrate (- x)
* simplex has jmps to jmps? extra crap

## bytecode perf improvements 

* Find max top of stack for add_snap and all ops.
* tail calls still do a mov/return for let().  see cat.scm

* could put memq/assq/length/map/append/string-append etc as intrinsics
* faster call/cc - flush frames w/underflow handler.  Overflow handler can also just flush frames.

* remove hotspot for non-jit / new bytecode
* could do special branches for 'char=', '=', where we know it is a quick-branch, and know it fits in 16 bits
* could do special opcodes for true, false.  basically return 'konst'

* 'sbuf' buffers for string ops?  substring / string append etc can be sped up substantially.

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
* make a 'vm state' struct, so we can run multiple vm's?
* remove indirection for consts/bc
* comments in output

# JIT TODO:

* various JIT improvements
  * 'loop' can know exact arguments in regs?  Or just not loopify at all?
  * save less in snap - dead elimination, read-only
  * we should be able to coalesce arg typechecks if they are the same.
  * Maybe a speical SLOAD EQ for RET instead, since we don't need to typecheck
  * Typechecks need a rethink - we can special case some stuff like eq?/eqv?, merge typechecks, etc.
  * load return slot only once somehow.  SLOAD -1, or RLOAD, or something.
      Only seems to matter for long strings of returns.  It should be in cache anyway, and we have to load
	  it at least once.
  * something something about GGET checks for func calls carried in snaps?

* All of 'RECORD' probably needs type tests when we access frame.

* need to purge snap to minimum entries. - kinda done, maybe a 'readonly' slot.  ONLY for sload, not ARG.
  * only matters for emit_snap

* a better GC, immix or bartlett

# OPTS

* dce
* global fetches
* mem - L2L + S2L, DSE, AA
* sink
* loop
* constant folding / sccp
