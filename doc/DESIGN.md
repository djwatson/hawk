# Prologue

I probably have the remenants of ~7 or more scheme interpreters /
compilers sitting around my hard drive.  What you see here is the most
successful of them - performance wise, it's one of the fastest schemes
anywhere, and one of the more unique.  

It's a tracing JIT heavily inspired by LuaJIT.  There were several
other tracing schemes - Nash, and pycket - but none of them seems to
compile well anymore, nor reach performance as good as chez.

I'm just a semi-retired guy with a side project, and as such this will
likely never be a complete scheme system.  But there's plenty of cool
stuff about it I want to share, so let's dive in.

# Overview

The whole frontend is written in scheme.  There are a series of
passes that run over bog-standard scheme AST.  The passes can be seen
running at the end of bc.scm.


They are:

* Macro expander - alexpander. 

Alexpander, with almost no modifications.  This limits us to roughly
r5rs scheme, and requires adding a bunch of extra passes to clean up
the output.

* add-includes

Adds includes in a cheesy way.  A r7rs-compliant expander would remove
this.

* case-insensitive 

r7rs is case insensitive, r5rs is not, and currently hawk doesn't
support #fold-case.

* integrate-r5rs

This inlines many r5rs primitives, in the same way many r5rs schemes
do.  The list is actually pretty small: 

* - + / < <= >= > = 
car cdr set-car! set-cdr! cons vector-ref vector-length string-length string-ref string-set! vector-set! 
char->integer integer->char symbol->string string->symbol
round vector eqv? quotient remainder zero? eq? char=? quote
not write-char pair? boolean? procedure? vector? string? port?
char? symbol? eof-object? flonum? fixnum? null? caar cddr cadr

All the scheme primitives are typechecked in the VM and not in scheme,
so no additional checks are needed, we are just removing a level of
indirection.

This mostly matters for the interpreter - the JIT would trace through
any function calls anyway (but caveat - if there are loops in the way,
as in the math operators and comparators, it doesn't work as well).

* alpha-rename

Rename everything uniquely globally, since alexpander only does it
per-branch and not globally.

* fix-letrec

The cheesy-est fixing of letrec you'll see.  Lambdas are fixed,
everything else is boxed.  The scheme benchmarks don't use internal
defines or letrec much at all - and hawk's toplevel is *not* compiled
to a letrec* - we have special optimizations for loading/calling
globals instead.

* assignment-conversion

Bog-standard assignment conversion - any set! lexicals (not globals)
get turned in to a cons, and set-car!'d.

* optimize-direct

Change direct calls back in to let.

* lower-case-lambda

Lower case-lambda calls a bit more.  Again, could be rolled in to a
better expander.

* inline-called-once

Try to find functions called only once, and inline them.  Note this
and integrate-r5rs are the only inlining passes in the bytecode -
there is no generic inliner until you hit the tracing JIT.  

This pass was found important to remove a few closure allocations though.

* lower-loops

Simple check for non-escaping functions that tail-call themselves, and
turn them in to loops.  The JIT would trace through these easily, but
they would still have to allocate closures.  Turning them in to loops
removes the need for an allocation.

* name-lambdas

A bit of debugging, try to find a pretty name for lambdas.  Static
analysis only.

* letrec-ify-prepass
* find-free
* update-direct-calls
* scletrec
* scletrec2
* final-free
* closure-conversion-scc

This is an implementation of "Optimizing closures in O(0) time", in a
bunch of passes.  Removing allocations is important for peak
performance.

And then finally, we hit the bytecode compiler:

## BC - bytecode compiler


The bytecode format is *very* similar LuaJIT: An opcode, a destination
register, and either a) two register operands or b) one register operand c) one large operand (which
may be unused).  It's a 'register-based' VM, in that all instructions
indicate a stack slot to operate on (the 'register'), and not just the
top-of-stack pushing and popping.

OP DEST A B
OP DEST C
OP DEST OFFSET
		
The compiler walks the AST, doing destination-driven code generation.
We allocate 'registers' (really stack slots) in a tree-driven fashion.
There are couple optimizations/complications: 

* References to function arguments use the argument stack slots, and
  don't move them: i.e. they're not destination driven, we have to
  check if something is an argument reference, adding a bit of
  complication.
  
* Math ops can have 'VV' and 'VN' variants: either register-register, 
  register-small constant. 
  
* Branches that are comparisons are implemented as separate opcodes.

* There is a bit of code to try and optimize *and* and *or* keywords
  and invert branches - but I don't think it works very well.
  
One consequence of allocating registers in tree-order, is that let and
letrec bound variables do not have precise lifetime info- they live
until the end of the scope, even if their last use is much sooner.
This means the JIT must keep snapshots to them around for perhaps
longer than it should.

The 'top of stack' is implicit in most opcodes (as can be seen in
record), so we know we only need to track up to that level of stack.
It would be nice to have more precise lifetime info in the future, so
at the very least dead let-bound variables would not be in the JIT's
snapshots, and hence carried around in registers in the trace.  (One
experiment here is that no benchmark uses more than ~60 registers, we
could use one bit to indicate 'last use' for each argument.  However,
there are still dead args at the start of branches, and after loops,
that we would have to keep track of also).

Opcodes themselves are *very* high level: For example, the ADD opcode
functions on all types of numbers, and must run typechecks. This makes
the bytecode extremely compact (there is no typechecking anywhere, and
makes traces extremely easy to read), at the downside of complications
in the VM itself.

The output of the bytecode pass is a serialized bytecode file.
Currently the serialization is pretty custom in bc.scm, and then
readbc.c.  I have experimented instead with serializing directly to a
GC-heap format, and it was actually much smaller and cleaner, at the
expense of baking in the GC-heap format.  Something for the future.

Serialization must also know how to serialize all types - including
flonums, bignums, etc.  Currently there is a bit of custom logic to
make this work for flonums.  

The bytecode format holds both functions and constants as globals.
Bytecode functions and constants are currently never freed.  Again,
serializing in a better way could fix this.

# VM

Great so we've got a bytecode file, can read in the functions and
constants.  How does it run?

The VM, unlike LuaJIT, is written in C.  It uses clang's musttail
convention to tail-call from one VM-op to another.  This is much more
portable than the custom ASM code for each LuaJIT VM, and tests for a
simple ASM in the style of luajit showed it was within 95% of custom
assembly.  

The one place where it falls over is if we use more
registers and we have to spill callee-save registers.  Since we are
tailcalling everywhere, we don't actually need to save callee-save
registers, but LLVM doesn't know this.  There are calling conventions
like GHCCC (cc10), or clang's newer PRESERVE-NONE that should help
with this.

The VM defines all the opcodes, and they are extracted with a script -
lib/opcode_gen.scm.  There are also a bunch of macros to help with
typechecking of arguments, and to avoid repeating too much code for
the comparison (branching and non-branching variants) and math
opcodes.  Unfortunately C's preprocessor is a bit weak, and it leads
to a messy experience that's hard to lint.

The VM has an 'opcode table' that jumps from one opcode to the next.
The table is replaced when profiling or recording.

The interpreter can be invoked with the jit off by either:

./hawk --joff

or compiling without jit:

cmake . -DJIT=off
make
./hawk

The VM is currently the fastest scheme VM I know if.  It is
competitive with chicken scheme's *compiler* much of the time 
(doc/benchmark_results.org).

# GC

Honestly, a simple semi-space GC does fairly well in the r7rs
benchmarks: There are only a couple benchmarks where a generational GC
beats it.  

Hawk uses an IMMIX-style reference counting GC:  and it's fairly
unfinished at that.  All young allocations happen in a traced nursery
space - anything that survives a single GC cycle is instead moved to a
slab-allocated RC-counted space.  RC counts are deferred/coalesced.

Currently none of the benchmarks have cyclic garbage structures that
survive past the nursery, so I haven't even fully implemented
backup-tracing.

One downside is that long linked-list structures take a long time to
free, and references to them are held over a GC cycle, so occasionally
more memory is used than, say, chez' GC.  Using background threads to
free would ameliorate the first problem somewhat.

Hawk is the best in GCBench easily, but because of the long free-time,
looses at some other GC-heavy benchmarks, like paraffins.  Mperm is
also an interesting GC test, chez is quite slow there.

# JIT

The JIT is almost almost identical to LuaJIT's: It is SSA, with a
single forward-pass of recording, and a single backwards-pass of
emitting instructions, some simple DCE, and register allocation.

Substantial changes include

* We can allocate extensively in traces: We won't run collections, but
  as long as there is bump-space, we can allocate cons cells,
  closures, etc.
  
* Tracing for recursive procedures is improved, since scheme relies
  heavily upon this.
  
* We *TYPE* the traces based on the arguments to the function or loop:
  I.e. fib(25) is a *different trace* from fib(25.0).  This was
  inspired by basic-block-versioning work done by marc feeley and
  friends.
  
* Similarly, the first X (currently 6) arguments are passed via
  register to all traces:  in LuaJIT, trace-exit dumps all the
  registers to a blob and lets the C code sort out how to put them
  back in the VM stack using a snapshot.  We do somewhat of the
  reverse: We use the starting snapshot to typecheck and put the first
  X arguments *in* registers.  
  
## Trace recording

* We record starting at LOOP instructions, for simple traces.

* We record at FUNC instructions, for recursive traces.
  The stack does *not* need to remain even for these: they can be
  up-recursive functions.
  
* For side traces, we also detect if something appears to be
  down-recursive.  We then abort, and restart on the RET instruction,
  attempting to record a down-recursive trace.
  
* Finally, if we have failed enough times to record a looping trace,
  we will actually just start at FUNC and record *non-looping* traces:
  Somewhat closer to what a method-jit would do.
  
Analysis shows that 95% of the code or more needs to run in the JIT.
Jit->VM and back transitions are heavy.

Tracing through call/cc is surprisingly simple - it's just an
extension of down-rec tracing: We have to check the return values, but
as long as they match, we can continue to trace.

Tracing through rest-args is also pretty easy: We have to record the
number of arguments we call with, but as long as the *number* is the
same, we're good. 

Generic apply calls aren't implemented, only small fixed number of arguments.
  
# PROFILER

The profiler was more complete at one point, but is now pretty sad.  I
used it extensively to profile the VM, since linux' perf tool doesn't
provide stack traces for VM instructions.  perf works just fine on
traces though (use the --dump option to dump perf-compatible
annotations.  See also test/hawk_record+report).

# OPTIMIZATIONS

Many/most of the LuaJIT optimizations haven't been done:

* OPT_LOOP - peel loops, such that we don't have to keep reloading
  values from the stack.  This is far less necessary in Hawk, since
  the first X arguments to *any* trace are put in registers, so
  loop-carried variables are probably not loaded from the stack
  anyway.
  
* FOLD - we don't fold anything currently.  Case stements result in
  many repeated equality checks - really only the last successful one
  is needed.   There are even many emitted const equality checks! doh.
* DCE - Could mostly be done in reverse while emitting code? 
        LuaJIT has it as a separate pass for some reason
* MEM - there's some simple support for not reloading globals, but we
  could do much more load/store analysis.
* SINKING - we don't do any allocation sinking.  It is surprisingly
  straightforward in LuaJIT.
  
And some that aren't applicable to LUAJIT:

* Global optimization:

Chez's optimizes globals bound to functions, by having a separate slot
for global functions that is called:  On the first call, it forwards
it to the global's values closure.  If instead it isn't a closure, an
error is signaled.  The *thunk* is reset if the global is ever set!.

For the jit, Hawk optimistically just inlines the global as a
constant value, and never checks it again.  If it is ever set!, we
flush that trace (and any side traces).  Subsequent traces will *not*
inline the constant value, and load the global.

* Monomorphic closure:

Similarly, closures that are monomorphic (we only ever create a single
closure for a single function pointer), we inline directly, and never
insert a check that the closure pointer matches. We again flush traces
if we detect additional closures created, and begin to check closure
pointers.

The combination of these two optimizations is that the vast majority
of toplevel is optimized as if it were a program, and yet will fall
back to the required behavior of a global is re-set. 

The downside is that once a global is set more than once, it will
always add additional checks (which we could warn on).



# TESTING

* Randomized trace-record testing.

In order to fully test the trace recorder, there is some code for
deterministic trace starting, based on a seed.  Givin the same seed,
and a deterministic program, we will deterministically make the same
traces.  Varying the seed, we should be able to get all the traces
(and trace ordering, and side trace creation, etc) possible.

* AFL support.  

This was hooked up to AFL at one point, so AFL could find branches
based on the seed.  

# Failed experiments

* *Forward* code emission / register allocation

I attempted to use Gnu Lightening (from guile), which requires
forward-emission of code.  This means register allocation has to be
done in advance: This gets slightly better spillage (since we know the
exact next use, while in reverse we can only guess that the farthest
definion is similar to the farthest use), but at the cost of carrying
a lot more liveness information around.   Probably not worth it.

Gnu Lightening also has limitations, such as only supporting
compare-and-branch, not supporting overflow checks on multiply, and
probably others.  Fixable, but annoying.  On the plus side, an aarch64
port would be easier.

# Other retrospectives

* Lots of the asm emission revolves around checking for consts and
  trying to do decent register allocation for them - unfortunately I
  think this is unavoidable, x86 requires folding constants in to math
  ops to get decent performance.
  
* The 'high-level' VM ops that result in good VM performance, also
  explode the length/complexity of record, since we also have to
  record the high-level, instead of having it broken down to simpler ops.
