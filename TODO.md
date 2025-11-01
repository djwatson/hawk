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

# simple VM

* c - because we need musttail, so only clang/llvm, zig, or asm seem to support it.
* use conservative collector on stack, but precise on heap, allowing dumping.
* Hmmm maybe allow toplevel and module - DON'T inline modules?  Or track which are inlined? ugh.
  * make this optional, I guess.
* generate VM and TRACE from single spec.
  * This makes things like error checking, and setting/getting stack slots, much more consistent.
* Loader should be agnostic to GC - symbols first, then funcs? Consts in a table per func?
  * non-moving GC from callcc.
* bytecode should FUNC should have frame size - do everything either
  SP or IP relative?  Don't store pointer to BC object if unnecessary.
* visualization of bytecodes.  SO helpful.

## tracer
  * backwards is waaaay easier
  * have some sort of emit like lightening that works for both aarch64 and x86_64
* visualization of traces
* register-ize first couple args. Keep track of type.
* dead/kills - no idea.  We could analyze bytecode, or just do
  top-of-stack tracking like previous.
* lazy typecheck - but then emit at the top.
* CALLT detect loops too
* multiple return values from the start
* punt on: more than 256 refs.
* emit LOTS of code, stubs for start/exit, don't make these interpreter loops, it's harder.

### opts

* fold 
   * gvn
* mem opts
* sinking
* loop? never really found useful
* dce - implicit.  Only useful with LOOP

