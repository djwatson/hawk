#### post mortem

# VM impl
* get PMOV guard working, check same as prev type
* to_flonum impl for GTE/sub
* Hmmm what happens if we abort because of typechecks???
* half finished - all the typcheck types
* half finished - currently we DO make multiple root traces, but they just get replaced.  DOH
   * need chaining, both in JIT code and linking from the first root trace.

* lazy typecheck - needs PMOV guard and loopback guards to be fixed still
* typechecking - add GUARD typechecks, probably for all types?

* math ops - fixnum,flonum, slowpaths.

* next: diviter, divrec, sumloop, nqueens.

* lookup check - fix expander thingy
* optimistic globals - TODO fail.  Also needs expander fix. need to support set!

* track stack-top
* spill slots

* rest of ops: cfunc, cfuncv, callcc/callcc_resume, guard, load/load_char, store/STore-char, integer->char/char->integer, apply, alloc, rest of cmps, rest of maths, exact/inexact, closure.  That's it.

* update stack overflow, just allocate a new section.

# cleanup
* remove frame_state, just modify **pc and **stack
* remove 'parent', use parent snap instead.
* we could improve emit_snap_store_flonum to use fewer registers / optimistic check for free

# simple VM

* debug info serialized - hmm maybe keep in scheme format?
* use conservative collector on stack, but precise on heap, allowing dumping.
  * this would be 'hard' if there are any saved continuations?  
     * actually maybe not, since it's just VM stuff on the stack (i.e. walk ret chain).
* Hmmm maybe allow toplevel and module - DON'T inline modules?  Or track which are inlined? ugh.
  * make this optional, I guess.
* Ugh, same with ARG: we can't know to drop it. Don't know if unused based on only trace, need
  usage info from .... something? either a post-pass live in JIT from BC, or pre-pass in compiler.

## tracer
* dead/kills - no idea.  We could analyze bytecode, or just do
  top-of-stack tracking like previous.
* multiple return values from the start
* punt on: more than 256 refs.

### opts

* fold 
   * gvn
* mem opts
* sinking
* loop? never really found useful, because reg-args covers most cases.
* dce - implicit.  Only useful with LOOP


# passes
* fix-letrec! - just check no letrec.
* assignment-convert! - just check no asssigned.
* recover-let
* loops
* name-lambdas
* closure convert simple! -   just check no free.
* output to BC.

* simple integerations for bytecode ops

## later:
* lift complex / bignums?
* count uses 
* advanced closure conversion (with subpasses)

## maybe?  probably unnecesary with jit:
* scev
* cp0
* type inference
  * storage use analsis?

# notes:

* using a VM forces us to reserve stack space for args, unlike a compiler. For large stack usage this results in higher memory use.  See sum1.scm
* ^^ no that's not it, it's that we need to save stack space by choosing order of evaluation for function call arguments! constants don't need to be saved on the stack and can be materialized later.
