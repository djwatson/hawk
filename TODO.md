# Currently working on:
* it looks like ir_load for non constant offsets needs to know type tag also
  old hawk had separate IR_REF and IR_VREF / IR_STRREFs for this.
* Trying to figure out ARG looping issue - we need to typetest BEFORE loopback.  
  sub-traces need to be side traces? Otherwise we can never make a null? check a real loop back to somewhere as a side-trace.  ugh. what to do?
* Similarly, add/sub need to actually do overflow checks so we keep type info.

# VM impl
* next: diviter, divrec, sumloop, nqueens.

* lookup check - fix expander thingy
* optimistic globals - TODO fail.  Also needs expander fix. need to support set!

* track stack-top
* spill slots
* half finished - all the typcheck types

* rest of ops: cfunc, cfuncv, callcc/callcc_resume, load_char, STore-char, integer->char/char->integer, apply, rest of cmps, rest of maths, exact/inexact.  That's it.

* update stack overflow, just allocate a new section.

# cleanup
* remove frame_state, just modify **pc and **stack
* remove 'parent', use parent snap instead.
* we could improve emit_snap_store_flonum to use fewer registers / optimistic check for free
* ir printing can use the ir type flags
* the skip_start_check could be generic, and we could cleanup NEW root traces etc. Not sure why it's not working, I made an attempt.
* cleanup setting of 'instr' in vmgen when changing recording state. 
  this only needs to be done in recording, not VM mode.
* we can do more register targetting of ending snapshot: we're always going here, if it is a side trace, we can target the orgiinal registers!
* args need to typecheck BEFORE entry to func:
  because on loopback we *already* know the arg type!
* extra unnecessary branch checks before regalloc
* fixup emit_tyupecheck for more than fixnum types


# scheme cleanup
* builders needs to be in with the rest of the IR passes. Use builders instead of backtick to build stuff.
* matchers kinda suck with annotations and unused fields, ugh???
* ir->sexp is used for debugging, we need a pretty-print IR I guess?
* move passes to separate file?

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

X fold 
   * gvn
* mem opts
* sinking
* loop? never really found useful, because reg-args covers most cases.
X dce - implicit.  Only useful with LOOP


# passes
X fix-letrec! - just check no letrec.
* assignment-convert! - just check no asssigned.
X recover-let
* loops
X name-lambdas
X closure convert simple! -   just check no free.
X output to BC.

X simple integerations for bytecode ops

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
