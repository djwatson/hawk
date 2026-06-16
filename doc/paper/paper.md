---
title: "Tracing Tail Calls: A Tracing JIT for Scheme"
author: "Dave Watson"
date: "\\today"
bibliography: references.bib
link-citations: true
header-includes: |
  \usepackage[outputdir=build]{minted2}
  \usemintedstyle{trac}
abstract: |
	Tracing JITs are an easy way to implement a JIT for dynamic languages.  They are often quicker than a full method JIT, while allowing incremental implementation.  They trace starting from inner loops, and add side traces to connect loops.  Scheme, however, does not contain loops: loops are implemented as recursion.  In this paper we explore implementing a tracing JIT for scheme, and in particular how we detect loops, up recursion, down recursion. We also implement polymorphic traces, and inlining of global assumptions to increase the performance of the JIT.   We show large speedups on flonum-heavy benchmarks due to unboxing flonums in the JIT, while non-flonum benchmarks are similar to other best-in-class scheme compilers.
---

<!--
dave's notes

- first args in reg, INCLUDING side trace->loop header.
- after a single loop, can return anywhere
- globals and closures can be 'promoted' to constants
- flonums in jit important, most stay in reg
- 'lazy' typecheck
- various with/without feature like loops, eager typecheck, globals/closures in reg, no IR_ARG, etc etc
  uprec/downrec? POLYmorphic traces!!!
- callcc in traces is EASY
- apply a little less so (finish this!)
- 
- TODO optimizations to add:
- integer range opt, helps sum not need overflow checks
- auto flvector, fft and nbody 
- sinking / alloc removal (probably dynamic, graphs)
- explicit type for ports (dynamic, read1, parsing, etc)
- opt_loop.  Not really sure 
-->

## Trace types

Traces are split in to several types: Root traces, which are always loops. They begin either at function headers or loop headers, when loop analysis is enabled.  Up-recursive traces are also loops, and are found nearly identically to root loops: They begin at the start of functions, with the only difference being the stack is not even when they end.  

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

The trace infrastructure described so far is very similar to how LuaJit functions [@pallluajit], but now we trod new ground. 

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

There are many cases where a closure is required, however, that closure is essentially a singleton, and only ever created once.  We track this on a per-function bases: if a function only has one closure created for it, we assume it is constant with the same mechanism as above, and all closure loads are also constant for it.

## Tracing call/cc

Currently all opcodes except APPLY are traced, including call-with-current-continuation.  At first glance it may seem hard to trace through a call/cc, but actually turns out to be quite easy: A call/cc entry makes an intrinsic call to the same C runtime function as the VM to save the current stack and package it as a closure, but otherwise is just a function call the same as any other.  

On call/cc return, or calling the captured closure, we currently insert a RET check, the same as a side trace, since we don’t statically know which continuation we’re returning to.  Additionally, an intrinsic call is inserted to replace the current continuation with the given continuation (exactly the same as the VM).  Then, we are able to continue tracing just as if there was no call/cc at all.

## Tracing case-lambda

Tracing case-lambda is quite simple in this system: Since function calls know the number of arguments they are making, and at the entry to each function, we check the argument count, we don’t even need to know the argument count after recording the trace: it is either on trace, or it takes a side exit.  We can package up rest-arguments on trace as well. 

The only exception is the APPLY opcode: we need to record apply, and then record which of the case-lambda cases we took.  We don’t want to overly constrain to the exact argument count, we only constrain to the number of fixed args, and call an intrinsic to package the rest list.  This means as long as the fixed args still match, we can handle any-length rest argument list.

## Analysis of trace types and trace stability

Currently <TODO insert table> our profiler shows >95% on-trace for all benchmarks, however, most of the scheme benchmarks are quite long.

During testing, a mode was implemented where a deterministic tracing schedule was used - normally traces are recorded when they are discovered to be hot with a (lossy) hotness counter.  When instead we record via deterministic schedule, we decide, in advance, that the X’th FUNC or LOOP will be recorded.  By using different starting seeds, we are able to trace in many different orders. This was initially used to shake out bugs in the trace emitter (i.e. bad register allocations).

It was found that using different seeds, the tracing was remarkably stable - the same number and location of root traces were found, and similar numbers of side traces, even though the traces were initially recorded in different orders.  <TODO insert table with stddev bars for trace counts and types>.  


## Tracing complications

The initial tracing infrastructure did NOT use or require LOOP analysis, and converting of some tail calls back in to loops.  However it was discovered that this analysis was important for removing ALLOCATIONS, not for helping the tracing infrastructure.  For example:

```scheme
(define (foo a) 
  (let loop ()
    (bar a)
	(loop a)))
```

If loop was de-structured to a function call, it would have to create a closure to hold a, while a LOOP bytecode will instead be able to load it from the stack.  

For a root loop ONLY this is not particularly important, since closures are constant, it will be able to constant-ify the closure load.  But if foo itself is in a loop, the closure will still have to be created every time, resulting in many more allocations than if we are able to stack-allocate a.  

This is the main downside of tracing that we’ve discovered so far: Since tracing functions inside-out, loops-within-loops result in worse behavior than if we were able to trace the whole double-loop together.   Allocations created in the innermost loop are able to be removed with allocation sinking, but if an allocation in the outer loop is passed to the inner loop, we are not able to remove it, since we never re-record the inner loop with new knowledge from the outer loop.


## Related work

### Pycket

Pycket is a tracing jit for racket, based on the pypy / rpython meta-tracing framework [@bauman2015pycket].  It implements a CEK virtual machine, which rpython is then able to JIT.  Using a generic meta-tracing framework has advantages and disadvantages: Pycket uses a much more complicated scheme to detect root traces: Either a combination of previous-PC and current PC (i.e. specific call locations), or a whole-program graph flow analysis.  This is probably due to restrictions in how rpython works.  

Rpython had already broken much ground on specific representation analysis, so auto-flvector support (and even unboxing of things like cons cells and boxes for assignment conversion) was easy to add.

Pycket’s choice of CEK machine also makes the usual trade off: continuation benchmarks like fibc or ctak are quite fast, to the detriment of any benchmark that is heavy on function calls but does not use continuations much.

### Nash

Nash is another tracing jit, based on guile’s VM [@hoshino2016nash]. Guile’s VM is very close to ours, and hence many of the benchmarks are quite similar.  However, guile is a mature system with many opcodes to implement, and Nash never did cover them all, so many traces abort with unimplemented opcodes

### Guile

Guile has acquired a JIT in recent versions, however, it is only a template JIT, so it does not do many optimizations, other than a tiny bit of register allocation [@guilejit].  For example, it does not do inlining at all.

### Overall Results

<!-- BENCHMARK_CHART -->

\begin{figure*}
\centering
\includegraphics[width=\textwidth]{generated/benchmark_percent_x64.pdf}
\caption{x64 Hawk runtime change relative to Chez. Negative values indicate that Hawk is faster; positive values indicate that Hawk is slower.}
\Description{Bar chart of x64 benchmark runtime changes relative to Chez.}
\end{figure*}

<!-- /BENCHMARK_CHART -->

### Flonum-Heavy Results

### Non-Numeric Results

### Ablation Study

### Trace Behavior

Trace behavior

---

## Discussion


### Limitations


### Future Work

---

## Related Work


---

## Conclusion

---

## Appendix A: Example Trace

TODO: Include one complete small example.


---


## Scratch Notes / Claims to Verify

- [ ] Mutual tail-call loops are supported / unsupported / partially supported.
- [ ] Global promotion has correct invalidation or guard behavior.
- [ ] Closure promotion is by identity / entry point / layout.
- [ ] Arity specialization is guarded correctly.
- [ ] Fixnum overflow exits correctly.
- [ ] Flonum fast path avoids generic dispatch.
- [ ] Side exits reconstruct interpreter state correctly.
- [ ] Compile time is included or separately reported.
- [ ] R7RS benchmark suite version is pinned.
- [ ] Results are reproducible from a clean checkout.

---

## References {.unnumbered}

::: {#refs}
:::

<!--  LocalWords:  JIT JITs inlining flonum flonums dave's args jit
<!--  LocalWords:  globals typecheck ARG uprec downrec POLYmorphic lj
<!--  LocalWords:  callcc TODO flvector fft nbody alloc Luajit NLF VM
<!--  LocalWords:  RET bytecode LuaJit aarch typechecking typechecked
<!--  LocalWords:  fixnum fixnums cdr pre LOOPs FUNC typechecks cddr
<!--  LocalWords:  divrec diviter inlined profiler lossy X’th stddev
<!--  LocalWords:  de ify Pycket pypy rpython CEK Pycket’s fibc ctak
<!--  LocalWords:  includegraphics textwidth Chez Arity usepackage
<!--  LocalWords:  outputdir usemintedstyle trac
 -->
 -->
 -->
 -->
 -->
 -->
 -->
 -->
 -->
