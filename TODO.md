#### post mortem

# VM impl

X GC needs to work in traces, faster fastpath somehow?
  * slowpath broken - some get_partial returning full partials for some reason
  * broken slowpath - we should not need refill(), just alloc_slow
  * fibfp broken on aarch ??
  * stack unbalanced on slowpath, getting prinf errors?
  * slowpath has explicit regs in emit, should be in backend

* lazy typecheck - needs PMOV guard and loopback guards to be fixed still
* typechecking
* math ops - fixnum,flonum, slowpaths.
X sumfp, fibfp

* lookup check - fix expander thingy
* optimistic globals - TODO fail.  Also needs expander fix. need to support set!

* track stack-top
* spill slots

# cleanup
* remove frame_state, just modify **pc and **stack
* remove 'parent', use parent snap instead.

# simple VM

* debug info serialized - hmm maybe keep in scheme format?
* use conservative collector on stack, but precise on heap, allowing dumping.
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
