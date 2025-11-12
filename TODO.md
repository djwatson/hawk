# VM impl

* maybe more test programs
* fix stack overflow

* typechecking
* math ops - fixnum,flonum, slowpaths.

* Actually, rethink BC: figure out stack top for EACH op.
   because unfortunately, IF doesn't have enough info.
* Ugh, same with ARG: we can't know to drop it.

* track stack-top
* argcnt check
* spill slots
* remove 'parent', use parent snap instead.
* use set in jmps?

# simple VM

* use conservative collector on stack, but precise on heap, allowing dumping.
* Hmmm maybe allow toplevel and module - DON'T inline modules?  Or track which are inlined? ugh.
  * make this optional, I guess.
* Loader should be agnostic to GC - symbols first, then funcs? Consts in a table per func?
  * non-moving GC from callcc.

## tracer
* Keep track of type.
* dead/kills - no idea.  We could analyze bytecode, or just do
  top-of-stack tracking like previous.
* lazy typecheck - but then emit at the top.
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

