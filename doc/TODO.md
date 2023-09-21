* gc: ctak, fft, earley, gcbench, paraffins, nboyer, sboyer, mperm 
# Getting all jit to work bench2

* loosing at: 
  * GC: diviter, divrec, gcbench, conform, sboyer, nboyer, earley, graphs, dynamic, peval, matrix, compiler, cpstak, deriv
  * closure analysis: nqueens
  * input/output buffering: wc, cat, dynamic
  * read: dynamic read1 sum1
  * call/cc: ctak, fibc
  * string ops: string, slatex, compiler, parsing
  * cpstak: GC, closure zeroing, various asm improvements, GC jumping out of trace
  * deriv: GC checks could be merged, leas, typechecks for store, also clearing of snapshots
  * lattice: asm ops, closure sinking, GC
  * dynamic: GC, read is super slow, read by char
  * parsing: unbox, closure-get need sccp
  * graphs: LOOP_opt, sccp, GC
  * ?? peval - sccp
  * ?? matrix - loop_opt, but also tracing??
  * ?? compiler - falling out of trace.  looping issue
  * puzzle - optimistic globals?

# TODO

* Better GC.
  * needs top-of-frame tracking.
    * clear snap from top
  * needs generational check for vector-set! set-cdr! set-car! set-box! gset
  * a better GC, immix or bartlett
  * GC doesn't need to jump out of trace for most things?
  * merge GC checks?
* sccp pass / fold
  * folding GGET: put in emit somewhere, check for GSET

* better closure allocation in frontend - full closure optimization
* singleton functions /closures
  * polymorphic / non polymorphic
* lazier typechecking
  * jguard counts as a use!
* TRACE loop recording - 
  * CALLT should also detect loops, and flush original trace??
  * compiler/matrix are tracing failures
  
* UNDEFINED_TAG
* fusion
* const pool
* cleanup register allocation - two-arg can be optimized

* input/output buffering
  * (read) in c?  Or buffer the string?
* LOOP_opt
* gvn / dce

* NYI:apply, close, file-exists?, open, delete-file, read-line
* enregister return arg??
* allocation sinking for cons/closure/vector
* reg hints across calls? and returns?
  * CALLXS betterness
* RET implementation could actually RET? faster somehow?

# working on

* 'closure' opcode should all be in the bcfunc prototype, and done behind a single opcode.
  * Do something to get rid of zero-initializing??
  * cleanup the second arg, can be inline instead of separate number

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

* various check for const size overflow, reg or opcode overflow

## VM cleanup
* make a 'vm state' struct, so we can run multiple vm's?
* remove indirection for consts/bc
* comments in output
* more precise top-of-stack tracking: Looks like it is off-by-one right now for some things
  like jmp and j* jumps

# JIT TODO:

* various JIT improvements
  * save less in snap - dead elimination, read-only
  * we should be able to coalesce arg typechecks if they are the same.
  * Maybe a speical SLOAD EQ for RET instead, since we don't need to typecheck
  * load return slot only once somehow.  SLOAD -1, or RLOAD, or something.
      Only seems to matter for long strings of returns.  It should be in cache anyway, and we have to load
	  it at least once.
  * something something about GGET checks for func calls carried in snaps?

* All of 'RECORD' probably needs type tests when we access frame.

* need to purge snap to minimum entries. - kinda done, maybe a 'readonly' slot.  ONLY for sload, not ARG.
  * only matters for emit_snap
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
