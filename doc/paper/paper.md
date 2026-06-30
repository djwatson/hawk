---
title: "Tracing Tail Calls: A JIT for Scheme"
author: "Dave Watson"
date: "\\today"
bibliography: references.bib
link-citations: true
header-includes: |
  \usepackage[outputdir=build]{minted2}
  \usemintedstyle{trac}
abstract: |
  In Scheme, iteration, mutual recursion, higher-order calls, and continuations all appear as control flow through function entries and returns, rather than as loops.  This paper presents Hawk, a tracing JIT specialized to control flow around tail recursion and function parameters.  Instead of treating Scheme programs as a special case of loop tracing, Hawk records and links traces at function call boundaries, categorizing traces as root loops, polymorphic, up-recursive, down-recursive, and links these traces together with additional side traces.

  The main payoff of this design is the ability to specialize functions to their types.  Hawk uses polymorphic trace entries to record distinct traces for calls with distinct entry types. The same scheme procedure can be specialized for flonums AND fixnums, and producing JIT code that is more efficient on current hardware.  Flonums remain unboxed and in register for hot loops.  Lazy type checks further reduce overhead by only guarding types that are known to be required for the trace.  Hawk also passes trace arguments in register, optimistically promotes globals and singleton closures to constants, yielding a dynamic yet fast JIT architecture without requiring whole-program analysis.  On the R7RS benchmark suite, Hawk reduces geometric-mean runtime relative to Chez scheme by 25%.
---

<!--
dave's notes

- [ ] Results are reproducible from a clean checkout.
 swap example for summix
 something something background: 
   1) scheme loops -> tail calls
   2) tracing types
   3) trace arguments
   4) polymorphism?
 remove comparisons to luajit ugh
 add luajit section
 more benchmark details:
  number of runs per benchmark;
whether numbers are min/median/mean;
whether CPU governor/turbo was controlled;
whether Chez was run with default options or optimize-level settings;
whether Hawk includes image startup time;
whether GC settings are default or tuned;
how geometric mean was computed;
whether benchmarks with failed/unsupported cases were excluded.

move GC section to maybe appendix? talking about all benchmarks?
Split ablation as much as possible, different const types,
try again to split reg. vs. poly

explain scheme loop construct btter

LLM suggested ordering:
Introduction
Problem: Scheme control flow is call/return/tail-call shaped.
Claim: trace at function boundaries.
Contributions list.
Headline results.
Background
Scheme tail calls, fixnums/flonums, tracing JIT basics.
Why normal loop tracing is awkward.
Hawk Overview
VM, bytecode, recorder, IR, trace ABI.
Tiny running example.
Trace Formation for Tail Calls
Root traces.
NLF/call-depth.
Side traces.
Up/down-recursive traces.
Trace linking.
Specialization
Register trace arguments.
Polymorphic root traces.
Lazy typechecking.
Constant globals/closures.
Scheme Features
call/cc.
case-lambda/apply.
closures and LOOP recovery.
Implementation
Backend/register allocation.
GC, image dumping, platform support.
Evaluation
Methodology.
Runtime vs Chez.
Flonum-heavy results.
Non-numeric results.
Trace counts/stability.
Memory/GC.
Ablation.
Related Work
LuaJIT.
PyPy/RPython.
Pycket.
Nash.
Guile.
Limitations and Future Work
Conclusion
-->

## Introduction

The scheme language has a very small core language, and requires tail-call optimization for all functions.  Many schemes do not even have a loop construct in their AST or compiler pipeline: all loops are represented directly as tailcalls.   Tracing JITs have often focused on loops as the location to start tracing.  We propose that any function call can become the start of a trace, and that this is enough to make a performant tracing JIT.

We also investigate specializing traces, so that both flonum and fixnum heavy benchmarks can be optimized.  Scheme has somewhat standardized on 61-63 bit fixnums, and double flonums.  Double flonums mean that flonums need to be boxed, since there is no space to differentiate a flonum from other things.   By recording distinct traces, we can unbox flonums to register, and keep them in register for the majority of hot loops.

\begin{figure*}
\centering
\includegraphics[width=\textwidth]{generated/trace_counts_x64.pdf}
\caption{x64 Hawk trace counts by benchmark. Stacked bars show normal-loop, side, up-recursive, and down-recursive trace counts.}
\Description{Stacked bar chart of x64 benchmark trace counts by type.}
\label{fig:trace_counts}
\end{figure*}

## Background

In Scheme, most loops are represented as tailcalls. In the r7rs report, even constructs such as `do` loops or `named let` loops are lowered to recursion.  This makes implementing a tracing JIT less straightforward at discovering loops.

Scheme supports a full numeric tower, however, many functions work on only fixnums or flonums at runtime (TODO: cite feely's inlining fixnum/flonum paper). Ideally a JIT would be able to use FPR hardware registers to hold flonums as long as possible instead of boxing them on the stack.

Standard scheme code also makes extensive use of uprecrusive and downrecursive traces, and often assumes stack space is not limited. For example, a somewhat standard `append` function might look like:

```scheme
(define (append2 a b) 
  (if (null? a) 
      b 
	  (cons (car a) 
	        (append2 (cdr a) b))))
```

The 'cons' is left on the stack as we build up the appended list.  Our JIT should still be able to generate efficient code for these, even though there is no obvious loop.

## System overview

### Compilation pipeline

Hawk uses a simplified scheme pipeline.  The r7rs expander is first, expanding libraries and macros.  Currently we only support syntax-rules macros, but this is not a hard limitation.

Several passes follow, such as fixing-letrec [@ghuloum2009letrec], assignment conversion, let-recovery, closure conversion [@keep2012closures], and loop recovery.  Currently we do inline a few base VM primitives, but there is no generalized inlining pass.

### VM bytecode

The VM is a tail-calling interpreter written in C.  Using tailcalls allows us greater control over VM state, allowing us to keep most variables in register.  Each VM bytecode decodes and tail-calls the next bytecode handler.   Opcodes are high-level: the ADD opcode can handle all scheme types, so all arithmetic is handled in C.  This keeps the VM quite fast.

### JIT recording & emission

FUNC opcode is used to do argument count checking, but also used as an indicator to check hotness and potentially start a trace.  When the hotness counter is exceeded, all opcode handlers are re-directed to first all the record() function, then the original handler.  The JIT recorder translates recorded bytecode ops to a lower-level IR format, closer to machine code.  The JIT IR only handles fixnums, flonums, and generic gc_obj boxed values: other arithmetic types call slowpaths, and call the same routines as the VM does, calling out of the trace to do so. In this way, the JIT can be thought of more as a 'inline as much as makes sense to do', but we can keep generic slowpaths the same as the VM for anything else.

The assembly emission uses a generic layer that abstracts the x64 and aarch64 backends: Things like memory addressing, constant emission, and math+ constants are all supported in the generic layer, and individual backends reserve a few registers to normalize for their individual needs.  For example, aarch64 needs everything to be in register first, so most constants require emitting the constant to a temp register, then adding, while for 32-bit constants, x64 can add directly.  Conversely, aarch64 supports fixnum div with any registers, while x64 requires explicit registers to be used, potentially requiring us to shuffle things around.  While some performance is lost in this process, it keeps the emission path quite clean and straightforward, without an additional lowering from the IR to an additional arch-specific IR later.

Register allocation is a generic backwards-liveness and spilling pass, and then a forward pass that runs during emission, that just chooses a register at random.  Since the backends already abstract over which exact registers are needed, we don't even do a full linear scan allocation.

### GC

We use a simplified variant of LXR [@zhao2022lxr].  We currently only support blocks, and have not yet implemented a backup tracing collector.  All heap objects also currently require an 8-byte header, meaning cons cells are 24 bytes.   With lookaside mark bits, this could be improved in the future.  However, even with these limitations, our GC is quite performant.  Here's a small selection of GC-heavy benchmarks, including peak RSS and exection time:

The GC supports image dumping & reload, and this is how bootstrapping the expander works: A host scheme is used to generate an initial heap image.  Then using a bootstrap hawk, we run the image, re-initialize the expander (the expander does not support serializing its current state).  Then we dump a final heap image, and build it in to the final executable. The heap image is compressed using ZSTD [@collet2021zstd], and the final binary is around half a MB for a full r7rs system.

## Trace types

Traces are split in to several types: Root traces, which are always loops. They begin either at function headers or loop headers, when loop analysis is enabled.  Up-recursive traces are also loops, and are found nearly identically to root loops: They begin at the start of functions, with the only difference being the stack is not even when they end.  

\begin{figure}[H]
\centering
\includegraphics[width=0.96\columnwidth]{generated/peak_memory_x64.pdf}
\caption{x64 peak memory usage of Hawk and Chez for GC-heavy benchmarks. Runtime labels (seconds) are shown on each bar.}
\Description{Grouped bar chart of x64 peak memory usage for Hawk and Chez across GC-heavy benchmarks.}
\label{fig:peak_memory}
\end{figure}

### Finding root loops

Root loops start at function headers, or loop headers, and continue tracing until we end at the SAME instruction header.  However, a naive trace may not capture a full loop.  For example:

``` scheme
(define (x a b) 
  (g a b) 
  (g a b) 
  (x a b))
```

If we started a trace at the start of g at the first call, the second call to g would result in running the same instruction, and hence end the loop.  Additional heuristics are needed to cause a trace to cover the full x loop, and not just the part between g.  For root and up-recursive traces, we count the call-depth, and if the call depth were ever to fall below 0, the trace is aborted.  For example, if a trace started at a call to g above, when g returned, the call depth would be below 0, and immediately abort.  If we start a trace at x, the call-depth during g would be 1, and return to 0 (twice for two calls to g), then call x.  Since in this example x is in tail position, we would NOT increment the call depth, so we would have a full loop.   If x was not in tail position, the depth at the end of the loop would be 1, resulting in an up-recursive trace. 

Luajit calls this ‘Natural Loop First’ (NLF) [@pallluajit]

### Side traces

Side traces may begin at any snapshot exit.  Side traces do NOT have the restriction that the depth cannot go below 0.  Once the depth is below 0, since the trace did not record where the call was from, we must guard that the return address is the same as when we recorded the trace.  This is done with the IR_RET instruction. 

Side traces are not restricted to ending at the same root trace - they end when they encounter *any* matching root trace (matching explained in X.X section).  

### Down recursive traces

Down recursive traces start and return at a returning bytecode op.  Since we don’t generally want to record a down-recursive trace without a matching up-recursive trace, down recursion is ONLY detected and started while on a side trace.  While side trace recording, we count how many RET instructions we’ve passed, and where they lead.  If we determine this may be down-recursion, we stop at the RET instruction, abort the current trace, and start recording a down recursive trace, which MUST end at the same RET instruction.  

Similarly to how down recursive traces are detected and tracing restarted, if we detect up-recursion in a side trace, we also abort the current trace and restart as an up-recursive traces.

Deciding exactly when to attempt a down-recursive trace is tricky.  We found empirically that restarting a side trace and restarting as down-recursive too early resulted in bad trace trees.  Currently we wait until we've seen at least two iterations of down-recursion, *before* even attempting a down-recursive trace.  Then, we will wait up to a random three *additional* iterations before starting the trace: It was found some programs attempt traces with an exact number of down-recursions, and then never actually succeed in capturing a down-recursive trace due to iteration count.  With some randomness in the process, down-recursion works across a wide range of programs. 

When an actual down-recursive trace is started, we only capture a *single* loop from RET to RET.  We do not currently unroll any loops, down-recursive or otherwise.

### Trace arguments in register

The trace infrastructure described so far is very similar to how LuaJit functions [@pallluajit], but now we tred new ground. 

Since traces begin at only function start, loop start, or return statements, we know the arguments to each of these.  We put in register the first X arguments given in each case (we currently match X to the calling convention of the target arch: 6 for x64, 8 for aarch64).  This means for loops or side traces connecting back to a root loop, most arguments stay in register the whole time, even without any additional loop optimization.  

LuaJit used ‘lj_opt_loop’ for the same purpose [@pallluajit] - it will automatically peel the first iteration of every loop, and figure out which stack loads need to be phis.  For root loops, this actually works even better, however, it does not work for side traces.  In testing on scheme code, it was found very important to get recursive calls and side traces to maintain register arguments as well. 

### Polymorphic traces

Root traces record the types of arguments on entry.   When we try to link back to this root trace (either from the same trace as a root loop, or from a side trace back too a root loop), we check if the incoming arguments match the previously recorded ones.  If so, we can push the typechecking back to the incoming trace, since many of the arguments are ALREADY typechecked there.  In addition, we maintain a linked-list of root traces all starting in the same location, but with different starting arguments.  This polymorphic splitting allows specialized traces to maintain entirely different traces, which is important for traces that use different types of registers, e.g. fixnum vs. flonum.  

As an example:

```scheme
(define (fib a) 
  (if (< a 2) 
    a 
    (+ (fib (- a 1) 
	   (fib (- a 2))))))
```

If we call (fib 40), we will eventually trace fib with a fixnum argument.  If later we call (fib 40.0), we will make an entirely new trace, with all flonum arguments.  This is different than inlining both flonum/fixnum fast paths , since we will never typecheck flonum or fixnum at all.  TODO better example, maybe sum, since this will box and put on stack anyway.  Show example traces.  Some schemes will only insert fast paths based on the numbers used, i.e. (< a 2.0) will assume flonums, while (< a 2) will assume fixnums.

After we discover an initial root loop however, additional polymorphic traces are NOT required to be loops, and function similarly to side traces, which may return and link to other root loops.  For example, a simplified list? Function:

```scheme
(define (list? a) 
  (or (and (pair? a) (list? (cdr a)))
      (null? a)))
```

The initial trace of list?  MUST be a pair type, otherwise it will never form a loop.  After the initial traces, additional polymorphic traces of type nil, or anything non-pair or non-nil, will start as additional polymorphic traces, however, they will never form a loop, so a root-loop-only restriction would be too narrow, and instead we allow them to return, and link to other root loops.

### Tracing through

In addition to polymorphic traces, we also allow side traces to ‘trace through’ an already-recorded trace instead of linking to it, if the trace arguments do not match.  Again, the list? example is informative: If a side traces called list? With an actual list, we WANT to link to the root trace, however if it is calling list? With nil, it will result in a SINGLE guard of type nil, so inlining the call in the existing side trace makes more sense.  This also allows unrolling of a small number of iterations of the loop before aborting (and eventually try tracing again)

### LOOP analysis

While we do not require any pre-analysis for loops to successfully trace, there is still a valid reason to turn any statically detectable recursion to a real LOOP opcode:  allocations.  LOOPs do not allocate at all, while looping by recursion may have to generate a closure.  We've found almost no bearing on tracing of LOOP vs FUNC (recursive) tracing, only allocations are affected.

### Lazy typechecking

The trace recorder records all types seen, but only lazily typechecks those that actually need a known type.  For example, taken from either divrec or diviter benchmarks, loading a cons cell does NOT automatically typecheck the value, or does storing it:

```scheme
(cons (car a) (cddr a))
```

`a` is typechecked to be a cons type, but the car of a is never typechecked, even though it is loaded to register, and stored back to a new cons cell.

## Promotion to constants

Several types are important to promote to constants in scheme: global variables are often constant, as are some closures.

### Constant globals

Globals in scheme are either top level global variables, or top level library variables.  Unlike other schemes, we do not enforce that top level library variables are immutable.  Globals are assumed to be immutable, and the value is inlined in any traces recorded as a constant.  If we later call set! On any global variable, all traces that made assumptions about that global are invalidated (the current system flushes *all* traces).  On all tests and the benchmark suite, this happens only very rarely, since usually a mutable global is discovered before we ever record a trace to it (and instead of a constant, we emit a normal global load in any traces involving that global).

### Constant closures

There are many cases where a closure is required, however, that closure is essentially a singleton, and only ever created once.  We track this on a per-function basis: if a function only has one closure created for it, we assume it is constant with the same mechanism as above, and all closure loads are also constant for it.

## Additional scheme tracing issues

### Tracing call/cc

Currently all opcodes except APPLY are traced, including call-with-current-continuation.  At first glance it may seem hard to trace through a call/cc, but actually turns out to be quite easy: A call/cc entry makes an intrinsic call to the same C runtime function as the VM to save the current stack and package it as a closure, but otherwise is just a function call the same as any other.  

On call/cc return, or calling the captured closure, we currently insert a RET check, the same as a side trace, since we don’t statically know which continuation we’re returning to.  Additionally, an intrinsic call is inserted to replace the current continuation with the given continuation (exactly the same as the VM).  Then, we are able to continue tracing just as if there was no call/cc at all.

### Tracing case-lambda

Tracing case-lambda is quite simple in this system: Since function calls know the number of arguments they are making, and at the entry to each function, we check the argument count, we don’t even need to know the argument count after recording the trace: it is either on trace, or it takes a side exit.  We can package up rest-arguments on trace as well. 

The only exception is the APPLY opcode: we need to record apply, and then record which of the case-lambda cases we took.  We don’t want to overly constrain to the exact argument count, we only constrain to the number of fixed args, and call an intrinsic to package the rest list.  This means as long as the fixed args still match, we can handle any-length rest argument list.

### Analysis of trace types and trace stability

Currently Figure \ref{fig:trace_counts} shows our profiler shows >95% on-trace for all benchmarks, however, most of the scheme benchmarks are quite long.

During testing, a mode was implemented where a deterministic tracing schedule was used - normally traces are recorded when they are discovered to be hot with a (lossy) hotness counter.  When instead we record via deterministic schedule, we decide, in advance, that the X’th FUNC or LOOP will be recorded.  By using different starting seeds, we are able to trace in many different orders. This was initially used to shake out bugs in the trace emitter (i.e. bad register allocations).

It was found that using different seeds, the tracing was remarkably stable - the same number and location of root traces were found, and similar numbers of side traces, even though the traces were initially recorded in different orders.  Figure \ref{fig:sd_variability} shows that runtime variability is also low across seeds.

### Tracing complications

The initial tracing infrastructure did NOT use or require LOOP analysis, and converting of some tail calls back in to loops.  However it was discovered that this analysis was important for removing ALLOCATIONS, not for helping the tracing infrastructure.  For example:

```scheme
(define (foo a)
  (let loop ()
    (bar a)
    (loop)))
```

If loop was de-structured to a function call, it would have to create a closure to hold a, while a LOOP bytecode will instead be able to load it from the stack.  

For a root loop ONLY this is not particularly important, since closures are constant, it will be able to constant-ify the closure load.  But if foo itself is in a loop, the closure will still have to be created every time, resulting in many more allocations than if we are able to stack-allocate a.  

This is the main downside of tracing that we’ve discovered so far: Since tracing functions inside-out, loops-within-loops result in worse behavior than if we were able to trace the whole double-loop together.   Allocations created in the innermost loop are able to be removed with allocation sinking, but if an allocation in the outer loop is passed to the inner loop, we are not able to remove it, since we never re-record the inner loop with new knowledge from the outer loop.


\begin{figure*}
\centering
\includegraphics[width=\textwidth]{generated/benchmark_percent_x64.pdf}
\caption{x64 Hawk runtime change relative to Chez. Negative values indicate that Hawk is faster; positive values indicate that Hawk is slower.}
\Description{Bar chart of x64 benchmark runtime changes relative to Chez.}
\label{fig:benchmark_percent}
\end{figure*}

\begin{figure*}
\centering
\includegraphics[width=\textwidth]{generated/time_breakdown_x64.pdf}
\caption{x64 Hawk runtime breakdown by benchmark. Stacked bars show VM, GC, and JIT time as percentages of total runtime.}
\Description{Stacked bar chart of x64 benchmark time broken into VM, GC, and JIT percentages.}
\label{fig:time_breakdown}
\end{figure*}

## Related work

### Pycket

Pycket is a tracing jit for racket, based on the pypy / rpython meta-tracing framework [@bauman2015pycket].  It implements a CEK virtual machine, which rpython is then able to JIT.  Using a generic meta-tracing framework has advantages and disadvantages: Pycket uses a much more complicated scheme to detect root traces: Either a combination of previous-PC and current PC (i.e. specific call locations), or a whole-program graph flow analysis.  This is probably due to restrictions in how rpython works.  

Rpython had already broken much ground on specific representation analysis, so auto-flvector support (and even unboxing of things like cons cells and boxes for assignment conversion) was easy to add.

Pycket’s choice of CEK machine also makes the usual trade off: continuation benchmarks like fibc or ctak are quite fast, to the detriment of any benchmark that is heavy on function calls but does not use continuations much.

### Nash

Nash is another tracing jit, based on guile’s VM [@hoshino2016nash]. Guile’s VM is very close to ours, and hence many of the benchmarks are quite similar.  However, guile is a mature system with many opcodes to implement, and Nash never did cover them all, so many traces abort with unimplemented opcodes

### Guile

Guile has acquired a JIT in recent versions, however, it is only a template JIT, so it does not do many optimizations, other than a tiny bit of register allocation [@guilejit].  For example, it does not do inlining at all, although the bytecode itself has been through a fairly strong inliner.  No type specialization is attempted.

### LuaJIT

LuaJIT [@pallluajit] is built around a similar bytecode interpreter & linear trace recorder.  Lua has explicit looping constructs, although LuaJIT does support uprec and downrec traces as well.  Its numeric types are NAN-boxed rather than doubles boxed in the heap.  All numeric types are represented as flonums in LUA, however, luajit has a pass to convert some of them back to fixnums.  LuaJIT contains other optimizations around tables that Scheme does not support, and its GC design is much different.

## Results

The standard r7rs-benchmarks suite [@r7rsbenchmarks], originally derived from the Larceny benchmark suite [@larcenists], is used. The x64 architecture was benchmarked on AMD Ryzen 9 5900X (ubuntu 25.10).  Chez version was 10.0.0.

Neither chez nor hawk times include compile time.  Hawk DOES include JIT time.  There is no jit warmup period.

Figure \ref{fig:time_breakdown} breaks total Hawk time into VM, GC, and JIT contributions on
the x64 run.

Figure \ref{fig:sd_variability} shows the runtime variability (standard deviation as a percentage of mean) across 30 random seeds for each benchmark on x64.  While the scheduler is randomized, the tracing and optimization decisions are remarkably stable.

\begin{figure*}[t]
\centering
\includegraphics[width=\textwidth]{generated/sd_variability_x64.pdf}
\caption{x64 Hawk runtime variability by benchmark (SD\% of mean over 30 seeds).}
\Description{Bar chart of runtime standard deviation as a percent of mean for each benchmark across 30 random seeds.}
\label{fig:sd_variability}
\end{figure*}

## Discussion

### Flonum-Heavy Results

The flonum heavy benchmarks are sum1, sumfp, simplex, ray, pnpoly, fibfp, fft, nucleic, sumfp, quicksort, mbrot.  These average more than 2x faster than the chez implementations.  While it is possible to explicitly optimize these in chez using fl- prefixed procedures and removing checks using optimize-level=3, Hawk is able to do this on generic benchmark code usable in any scheme.

### Non-Numeric Results

Only a handful of non-numeric benchmarks stand out.  

Closure capture is not very optimized: `fibc` and `ctak` are almost twice as slow. However, benchmarks that use call-with-current-continuation, such as puzzle, don't show meaningful slowdown.

The `dynamic` benchmark is slower, mostly due to the GC: a tracing GC is much faster than an RC gc for this, since dynamic creates many cycles. 

Other benchmarks show minor regressions.  Since Hawk is quite new, there is still plenty of generic optimization opportunities to be had.

### Ablation Study

The ablation study compares each Hawk variant against the baseline
`results.Hawk` run. Each bar shows the mean runtime as a percentage of the
original benchmark time, with asymmetric error bars showing the 16th to 84th
percentile range across the benchmarks included in the comparison.

\begin{figure}[H]
\centering
\includegraphics[width=0.96\columnwidth]{generated/ablation_runtime_x64.pdf}
\caption{x64 Hawk ablation runtime relative to the baseline. Bars show mean runtime as a percentage of the original `results.Hawk` time, with asymmetric error bars showing the 16th to 84th percentile range.}
\Description{Bar chart of x64 Hawk ablation runtime as a percent of baseline, with asymmetric error bars.}
\label{fig:ablation_runtime}
\end{figure}

Promotion of globals and closures to constants has the greatest effect. Currently the bytecode generator does NOT assume ANY globals (including in r7rs libraries) are constant, so this is entirely left up to the JIT to optimize.  One large benefit is that the user can still redefine library procedures at runtime, unlike most r7rs compilers.

Eager typechecking appears to only contribute a small amount to overall runtime.  The opportunites to drop typechecking are generally small (values don't need to be checked for some loads and stores, eq? and some eqv? can drop typechecking as well).

As predicted, dropping the LOOP analysis in the bytecode compiler only has a tiny effect - tracing works just as will with or without explicit static loop discovery.  Almost all of this performance is from additional closure allocations.

Enregistering the first X (currently 6) arguments, and making traces polymorphic, lends a large speedup (it was hard to disentangle these two things in the code to disable only one, and polymorphic currently requires register arguments).  Clearly keeping everything in registers is a large advantage, as it is with normal method-based compilers.

### Limitations

Hawk currently only supports ascii strings.  Only the bv2string benchmark would significantly change performance if unicode support were added.

### Future Work

There are many optimizations that haven't been added to Hawk yet, or showed only middling results: 

* loop peeling 
  
  Both luajit and pypy have a 'loop peeling' optimization, where root loops can be unrolled once, and then the normal CSE/fold pass applied.  We attempted this with Hawk, but it added much register allocation complexity, and only the 'puzzle' benchmark showed clear wins.  The issue is root loops that have SLOADs in them: the LOOP did not include them in registers, so they get reloaded each iteraton
  
* allocation sinking

  No benefit was found when applying this to Hawk and the benchmark suite: this is probably much less useful in scheme, due to multiple value returns (which all can stay in stack/register already) and case-lambda calls (so even calls with varying argument count stay in register).  Only a few infrequently called side-traces seemed to hit the optimization path.  We've left this out for now, again due to the large complexity it adds.
  
* The GC could still use much improvement

  Currently the root set is large, including all traces.  Suboptimal block / line sizes are used, and there is currently no backup SATB tracer, as mentioned in the LXR [@zhao2022lxr] paper.  Some things, like decrements and SATB cycle tracing, could be done in a background thread.  Currently none of the GC is thread-safe, which is the main item preventing Hawk from supporting threads.
  
* Integer range analysis

  Pypy has this, and would help on some of the sum benchmarks: Currently all fixnum ADD/SUB/MUL operations are checked for overflow in the JIT, while with range analysis we could drop some of overflow checking.  Range analysis could also be used to drop some of the bounds checking, if it can be proven that we can't exceed bounds.  LuaJIT combines this with a loop peeling optimization, so it only happens in loops.
  
* Other flonum representations

Currently Hawk unboxes flonums to registers where possible, including passing them between traces.  However, if placed in the heap, they are still boxed.  Other flonum representations include Nan-tagging (or nun-tagging), and 'Float self-tagging' [@melancon2025float].   Nan-tagging does not seem to work for the existing scheme code: for example, the current 'sum' benchmark requires large 60+bit fixnums, if we limited fixnums to only 32 bits, the sum benchmark would overflow to a bignum, significantly slowing it down.  We are not aware of a single scheme implementation using Nan-tagging for this reason. 

Float self-tagging would work as a replacement for boxing on the stack.  However, combined with auto fl-vector support, almost no benchmarks hit perf issues due to boxing flonums anyway, so this has not yet been tried.   It would also likely slow down other benchmarks, due to using ~3 of the available 8 low bit tags, vs. the 1 used now.  Likely string or symbol checks would have to be moved to header checks instead.

---

## Conclusion

The results for Hawk seem to support the theory that no static loop analysis is needed for languages without explicit loops: a tracing JIT can recover enough loop information only from recursive function calls.   

---


::: {#refs}
:::

<!--  LocalWords:  JIT JITs inlining flonum flonums dave's args jit
  LocalWords:  globals typecheck ARG uprec downrec POLYmorphic lj
  LocalWords:  callcc TODO flvector fft nbody alloc Luajit NLF VM
  LocalWords:  RET bytecode LuaJit aarch typechecking typechecked
  LocalWords:  fixnum fixnums cdr pre LOOPs FUNC typechecks cddr
  LocalWords:  divrec diviter inlined profiler lossy X’th stddev
  LocalWords:  de ify Pycket pypy rpython CEK Pycket’s fibc ctak
  LocalWords:  includegraphics textwidth Chez Arity usepackage
  LocalWords:  outputdir usemintedstyle trac
-->
