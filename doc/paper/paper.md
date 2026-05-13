---
title: "Tracing Tail Calls: A Scheme-Specific Tracing JIT"
author: "David Watson"
date: "\\today"
bibliography: references.bib
link-citations: true
abstract: |
  TODO: Write this last.

  Possible draft:

  This paper presents a tracing just-in-time compiler for Scheme that adapts trace formation to Scheme's execution model, where loops are commonly expressed as tail calls rather than backward branches. The system detects hot tail-call cycles, records traces through stable Scheme control paths, and specializes those traces using Scheme-level facts including procedure identity, closure layout, global binding stability, arity, and numeric representation. On the standard R7RS benchmark suite, the JIT provides large speedups on flonum-heavy benchmarks while remaining near break-even on most non-numeric workloads. These results suggest that a compact tracing JIT can significantly accelerate numeric Scheme programs, but that broader gains require additional optimization of allocation, higher-order calls, and symbolic workloads.

  TODO: Replace vague phrases with actual measurements. State the benchmark suite precisely. State the baseline precisely. Avoid claiming more novelty than the evidence supports.
---

<!--
dave's notes

- first args in reg, INCLUDING side trace->loop header.
- after a single loop, can return anywhere
- globals and closures can be 'promoted' to constants
- flonums in jit important, most stay in reg
- 'lazy' typecheck
- various with/without feature like loops, eager typecheck, glogals/closures in reg, no IR_ARG, etc etc
  uprec/downrec? POLYmorphic traces!!!
- callcc in traces is EASY
- apply a little less so (finish this!)
-->

## Introduction

Scheme implementations face a difficult performance tradeoff. The language encourages small procedures, higher-order programming, closures, proper tail calls, generic arithmetic, dynamic binding environments, and interactive redefinition [@sussman1998scheme; @r7rs; @dybvig2009scheme]. These features are attractive to programmers but complicate traditional ahead-of-time compilation and conventional loop detection.

Tracing JIT compilers can be a good fit for dynamic languages because they optimize hot execution paths rather than entire programs [@gal2009tracemonkey; @bolz2009pypy; @pallluajit]. However, many tracing systems identify loops using syntactic or bytecode-level backward branches. In Scheme, many loops are not represented as explicit backward branches at all. They are tail calls: self-recursive procedures, named `let` loops, or mutually recursive functions.

This paper presents TODO: system name, a tracing JIT for TODO: Scheme implementation. The system adapts tracing to Scheme by treating hot tail-call recurrence as a loop-discovery mechanism. It records traces across stable tail-call paths and specializes those traces using runtime facts about closures, global bindings, procedure entrypoints, arity, and numeric representations.

The implementation is evaluated using the standard R7RS benchmark suite. The main result is TODO: summary of benchmark result, for example: "large speedups on flonum-heavy programs, up to TODO×, while most other benchmarks remain within TODO% of the interpreter baseline."

### Contributions

This paper makes the following contributions:

1. **Tail-call loop discovery for tracing Scheme.**  
   The JIT identifies hot loops through repeated tail calls rather than relying only on bytecode backward branches.

2. **Scheme-specific trace boundaries.**  
   The system starts, stops, and links traces according to Scheme control-flow events such as procedure entry, tail calls, arity checks, and unknown calls.

3. **Runtime promotion of Scheme-level facts.**  
   The JIT promotes stable globals, closure identities, closure layouts, procedure entrypoints, arity, and numeric representations into guarded assumptions.

4. **Empirical evaluation on R7RS benchmarks.**  
   The evaluation shows that the JIT gives large improvements for flonum-heavy code while generally breaking even on non-numeric workloads.

TODO:
- Decide whether "order of magnitude" is supported by the final data.
- Mention whether speedups are against the interpreter, against JIT-disabled Hawk, or against other Scheme implementations.
- Add one sentence about limitations.

---

## Background

### Scheme Execution Model

TODO: Explain only the Scheme features needed for this paper. Avoid writing a full Scheme tutorial.

Relevant features:

- proper tail calls;
- first-class procedures;
- closures and captured variables;
- generic arithmetic;
- dynamic procedure calls;
- top-level and library bindings;
- possible global redefinition or mutation;
- fixnums and flonums;
- optional: multiple values, `apply`, rest arguments, continuations, if relevant.

Important point:

> In Scheme, loops are often procedure calls. A named `let`, for example, is naturally compiled as a recursive procedure whose recursive edge is a tail call.

Example:

```scheme
(let loop ((i 0) (sum 0.0))
  (if (= i n)
      sum
      (loop (+ i 1) (+ sum x))))
```

TODO:
- Describe how this is represented in Hawk bytecode or VM internals.
- Show a bytecode snippet if useful.
- Explain whether named `let` becomes an actual procedure/closure in Hawk or whether some cases are compiled specially.

### Tracing JIT Compilation

A tracing JIT observes program execution, identifies hot paths, records operations along those paths, and compiles the resulting trace into machine code. Guards protect assumptions made during recording. If a guard fails, execution exits the trace and resumes in the interpreter or another compiled trace.

Terms used in this paper:

- **Trace:** TODO: define in Hawk terms.
- **Guard:** TODO.
- **Side exit:** TODO.
- **Snapshot:** TODO.
- **Promotion:** TODO.
- **Trace root:** TODO.
- **Tail-call loop:** TODO.

TODO:
- Keep this section conceptual.
- Save detailed comparisons to LuaJIT, PyPy, TraceMonkey, etc. for Related Work.

### Why Scheme Is Awkward for Conventional Tracing

Conventional tracing systems often start traces at hot loop headers identified by backward branches. Scheme complicates this in several ways:

1. Many loops are compiled as tail calls.
2. Tail calls may target closures rather than fixed bytecode labels.
3. Higher-order calls obscure the callee until runtime.
4. Generic arithmetic and global variable lookup introduce dispatch overhead.
5. Proper tail calls require stack behavior different from ordinary calls.
6. Short symbolic benchmarks may not run long enough to amortize compilation.

TODO:
- Add a concrete example where a bytecode-backward-branch detector would miss a Scheme loop.
- Add a contrasting example where a normal branch inside a function is not itself a loop.

---

## System Overview

TODO: This is the map of the machine.

The implementation consists of:

- bytecode interpreter;
- hotness counters;
- trace recorder;
- intermediate representation;
- optimizer;
- machine-code backend;
- side-exit mechanism;
- runtime support for guards and fallback.

Possible diagram:

```text
source -> compiler -> bytecode
                       |
                       +-> interpreter
                       |
                       +-> recorder
                           -> IR
                           -> optimizer
                           -> machine code
```

TODO:
- Replace with a better diagram later.
- Include a table of important bytecodes if useful.

### Baseline VM

TODO:
- Describe the VM architecture.
- Stack-based or register-based?
- How are calls represented?
- How are tail calls represented?
- How are closures represented?
- How are globals represented?
- What bytecodes matter most for tracing?

### Value Representation

TODO: Fill in the exact representation.

Suggested subsections:

- fixnums;
- flonums;
- pairs, vectors, strings;
- closures;
- booleans, null, EOF, undefined;
- global binding cells.

Important point to explain:

> Numeric fast paths rely on guarding that values have stable numeric representations and then using unboxed machine operations within the trace.

TODO:
- Explain boxing/unboxing points.
- Explain overflow handling for fixnums.
- Explain flonum allocation or unboxing policy.

### JIT Pipeline

TODO: Describe the pipeline concretely.

Possible pipeline:

1. interpreter counts hot execution events;
2. hot tail-call target becomes a trace candidate;
3. recorder observes one execution path;
4. trace IR is emitted;
5. guards and snapshots are attached;
6. trace is optimized;
7. machine code is emitted;
8. future execution enters compiled trace;
9. guard failure exits to interpreter or another trace.

TODO:
- Add actual details from Hawk.
- Mention whether the JIT is method-based, trace-based, or hybrid.
- Mention whether traces are single-entry/single-exit, multi-exit, linked, etc.

---

## Tail-Call Loop Discovery

This is probably the paper's central technical section.

### Problem

In many bytecode systems, a loop can be detected by a backward branch. In Scheme, the most important loop idiom is often a tail call. A compiler may represent a named `let` or recursive function as a procedure call whose target is the current procedure or a mutually recursive procedure.

TODO:
- State exactly how Hawk observes tail calls.
- State what runtime event increments the hotness counter.
- State whether hotness is associated with the caller, callee, call site, bytecode PC, closure entrypoint, or some combination.

### Self Tail Calls

TODO: Explain the easy case.

Example:

```scheme
(define (sum-loop i acc n)
  (if (= i n)
      acc
      (sum-loop (+ i 1) (+ acc i) n)))
```

A self tail call creates a dynamic recurrence: control returns to the same procedure entrypoint with new arguments and no additional continuation frame.

TODO:
- Explain how this becomes a trace root.
- Explain where recording starts.
- Explain where recording stops.
- Explain how arguments become loop-carried variables.

### Named `let`

TODO: Explain whether named `let` is just a special case of self tail calls or has a distinct representation.

Example:

```scheme
(let loop ((i 0) (acc 0))
  (if (= i n)
      acc
      (loop (+ i 1) (+ acc i))))
```

TODO:
- Show source-to-bytecode lowering if it helps.
- Explain whether the JIT sees this as a procedure loop.

### Mutual Tail Calls

TODO: Decide whether this is supported, partially supported, or future work.

Example:

```scheme
(define (even? n)
  (if (= n 0) #t (odd? (- n 1))))

(define (odd? n)
  (if (= n 0) #f (even? (- n 1))))
```

Questions to answer:

- Can a trace span multiple procedure entrypoints?
- Are mutually recursive tail calls treated as one loop or multiple traces?
- Does trace recording stop at a different entrypoint?
- Are targets guarded by procedure identity or entrypoint identity?

### Trace Start and Stop Rules

TODO: This needs to be crisp and maybe include pseudocode.

Possible rules:

- start recording when a tail-call target exceeds a hotness threshold;
- stop when execution returns to the same trace root;
- stop at unsupported bytecodes;
- stop at unstable call targets;
- stop at non-tail calls, or record through known non-tail calls if supported;
- abort recording on excessive trace length;
- abort recording on too many side exits.

TODO: Replace with actual rules.

Possible pseudocode:

```text
on_tail_call(target, args):
    key = trace_key(target)
    count[key] += 1
    if count[key] == HOT_THRESHOLD:
        begin_recording(key, target, args)

while recording:
    record_next_bytecode()
    if unsupported_operation:
        abort_trace()
    if tail_call_to_root:
        close_trace()
    if trace_too_long:
        abort_or_compile_partial_trace()
```

TODO:
- Make this pseudocode match the implementation.
- Explain what `trace_key` contains.

---

## Trace Recording and IR

### Trace IR

TODO:
- Describe the IR.
- Is it SSA-like?
- Is it linear?
- Does it distinguish boxed Scheme values from unboxed machine values?
- How are guards represented?
- How are runtime calls represented?
- How are allocations represented?

Possible table:

| IR operation | Meaning | Notes |
|---|---|---|
| `guard_fixnum` | TODO | TODO |
| `guard_flonum` | TODO | TODO |
| `add_fixnum` | TODO | TODO |
| `add_flonum` | TODO | TODO |
| `guard_proc` | TODO | TODO |
| `load_global` | TODO | TODO |
| `guard_global_version` | TODO | TODO |
| `side_exit` | TODO | TODO |

### Guards

TODO: Explain the guard model.

Likely guards:

- value is fixnum;
- value is flonum;
- fixnum operation does not overflow;
- global binding cell has expected value or version;
- closure has expected entrypoint;
- closure has expected layout;
- procedure has expected arity;
- branch condition follows recorded path;
- vector/string/pair has expected type.

TODO:
- Which of these are implemented?
- Which are future work?
- How expensive is a guard?
- Where does a guard exit to?

### Snapshots

TODO: This is important for credibility.

A snapshot records enough state to resume execution outside the trace when a guard fails.

Explain:

- what values are saved;
- how interpreter stack state is reconstructed;
- how live locals are mapped;
- how loop-carried values are represented;
- whether snapshots are compressed;
- whether snapshots store boxed values, unboxed values, or recipes for reconstruction.

TODO:
- Include a small example trace and its snapshot.

### Side Exits and Trace Linking

TODO:
- What happens when a guard fails?
- Does the system always return to the interpreter?
- Can side exits become hot and compile new traces?
- Can side exits be patched to compiled traces?
- How is correctness preserved?

---

## Scheme-Specific Specialization

This is the other major technical section.

### Global Binding Promotion

Scheme global lookup can be expensive if every access must consult a dynamic environment or binding cell. If a global binding is stable during trace recording, the JIT can promote it into a guarded assumption.

TODO:
- Describe Hawk's global representation.
- Are globals binding cells?
- Is there a version counter?
- Does mutation invalidate traces or cause guard failure?
- How are imported library bindings handled?

Possible claim:

> Global promotion allows calls to primitives such as `+`, `<`, `fl+`, or vector operations to avoid repeated dynamic lookup inside hot traces.

TODO:
- Make this precise. Do not claim primitive names that do not exist.

### Closure and Procedure Promotion

Higher-order calls are common in Scheme. During tracing, a call site may repeatedly target the same closure or procedure. The JIT can specialize the call path by guarding the observed closure identity or entrypoint.

TODO:
- Which fact is promoted: object identity, entrypoint, code pointer, arity, closure layout, or all of these?
- Can two closures with the same entrypoint but different free variables share compiled paths?
- Are free variables loaded directly from the closure?
- Are closure-free procedures called without a closure argument?
- How does this interact with your closure-sharing policy?

### Arity Specialization

TODO:
- Explain fixed arity checks.
- Explain rest arguments if supported.
- Explain `apply` if supported.
- Explain what happens on wrong arity.

Important question:

> Is arity checked before entering a trace, inside the trace, or both?

### Numeric Specialization

Numeric specialization is the most visible performance win.

TODO:
- Explain generic arithmetic baseline.
- Explain fixnum fast paths.
- Explain overflow guards.
- Explain flonum fast paths.
- Explain boxing/unboxing.
- Explain fallback to generic arithmetic.

Possible benchmark-oriented paragraph:

> Flonum-heavy benchmarks benefit because traces remove repeated generic arithmetic dispatch and keep intermediate values in unboxed machine registers. This turns a loop that would otherwise allocate or dispatch on each arithmetic operation into a small sequence of floating-point machine instructions plus guards.

TODO:
- Verify against actual implementation.
- If flonums are boxed at loop boundaries only, say that.
- If flonums are still boxed internally, do not claim otherwise.

### Tail Calls and Proper Tail Recursion

TODO:
- Explain how compiled traces preserve proper tail calls.
- Does entering a trace allocate a call frame?
- Does a tail call inside a trace reuse the current frame?
- How are interpreter and compiled stack states reconciled?

---

## Optimization and Code Generation

### Optimization Passes

TODO: List implemented optimizations only.

Possible optimizations:

- constant folding;
- guard simplification;
- redundant type-check elimination;
- common subexpression elimination;
- dead code elimination;
- numeric unboxing;
- branch folding;
- bounds-check elimination;
- allocation sinking;
- trace stitching.

TODO:
- Mark unimplemented ideas as future work, not as existing features.

### Register Allocation

TODO:
- Describe the register allocator.
- Linear scan? Reverse linear scan? Simple fixed-register lowering?
- How are live values at guards handled?
- How are values spilled?
- How are snapshots related to spills?

### Machine Code Backend

TODO:
- Target architecture: x86-64, AArch64, both?
- Calling convention.
- Runtime calls.
- Guard failure stubs.
- Code memory allocation.
- Trace entry protocol.
- Trace exit protocol.

---

## Evaluation

This section should be empirical and conservative.

### Methodology

TODO:
- Machine specs.
- OS and compiler.
- Hawk commit hash.
- Build flags.
- Benchmark suite version.
- Number of runs.
- Warmup policy.
- Timing method.
- Whether GC time is included.
- Whether compile time is included.
- Statistical reporting: median, min, mean, standard deviation.

Recommended reporting:

- use median of N runs;
- include compile time unless clearly separated;
- report speedup relative to Hawk interpreter;
- separately report comparison against other Scheme implementations.

### Benchmarks

TODO: List the exact R7RS benchmarks used.

Suggested classifications:

- Flonum-heavy numeric: large JIT win.
- Fixnum-heavy numeric: moderate to large win.
- Allocation-heavy symbolic: break-even or slight loss.
- Higher-order/control-heavy: mixed.
- Short-running/startup-heavy: compile overhead dominates.

TODO:
- Classify actual benchmarks after measuring.
- Do not force the classification if the data disagrees.

### Baselines

Suggested baselines:

1. Hawk interpreter, JIT disabled.
2. Hawk JIT enabled.
3. Optional: Hawk JIT with selected optimizations disabled.
4. Other Scheme implementations for context:
   - Chibi;
   - Gambit;
   - Guile;
   - Chez;
   - Larceny or Loko if easy and fair.

TODO:
- Be clear that mature compilers are context, not necessarily direct apples-to-apples baselines.
- Explain interpreter vs native compiler differences.

### Overall Results

TODO: Insert main results table.

<!-- BENCHMARK_CHART -->

\begin{figure*}
\centering
\includegraphics[width=\textwidth]{generated/benchmark_percent_x64.pdf}
\caption{x64 Hawk runtime change relative to Chez. Negative values indicate that Hawk is faster; positive values indicate that Hawk is slower.}
\Description{Bar chart of x64 benchmark runtime changes relative to Chez.}
\end{figure*}

\begin{figure*}
\centering
\includegraphics[width=\textwidth]{generated/benchmark_percent_aarch64.pdf}
\caption{aarch64 Hawk runtime change relative to Chez. Negative values indicate that Hawk is faster; positive values indicate that Hawk is slower.}
\Description{Bar chart of aarch64 benchmark runtime changes relative to Chez.}
\end{figure*}

<!-- /BENCHMARK_CHART -->

Example result fields:

- benchmark;
- Hawk interpreter time;
- Hawk JIT time;
- speedup;
- category.

TODO:
- Use seconds or milliseconds consistently.
- Report speedup as baseline / JIT.
- Highlight geometric mean only if meaningful.

### Flonum-Heavy Results

TODO: This is likely the strongest results subsection.

Questions to answer:

- Which benchmarks improve the most?
- Are gains caused by unboxed flonum arithmetic?
- Are generic arithmetic dispatches removed?
- How much trace compilation occurs?
- How many exits occur?

Possible paragraph:

> The largest speedups occur in flonum-heavy benchmarks. These programs execute long-running numeric loops with stable operand types, allowing the recorder to produce traces with few side exits. Once compiled, the traces avoid repeated generic arithmetic dispatch and execute mostly floating-point machine operations.

TODO:
- Replace with concrete evidence.

### Non-Numeric Results

TODO: Be honest.

Possible paragraph:

> On most non-numeric benchmarks, the JIT is approximately break-even with the interpreter. These benchmarks spend more time in allocation, symbolic dispatch, list traversal, or runtime calls, and they expose fewer long stable numeric traces. This suggests that the current tracing strategy successfully avoids major slowdowns on general workloads, but does not yet optimize enough of Scheme's symbolic execution model to produce broad speedups.

TODO:
- Add actual data.
- Identify slowdowns honestly.
- Explain whether compile overhead, guard exits, GC, or unsupported operations are the cause.

### Ablation Study

TODO: Add if feasible. This would strengthen the paper a lot.

Possible ablations:

- JIT without flonum specialization.
- JIT without global promotion.
- JIT without closure promotion.
- JIT without side-exit linking.
- JIT with higher/lower hotness threshold.

Example ablation fields:

- configuration;
- flonum speedup;
- overall speedup;
- notes.

TODO:
- Even one or two ablations are useful.

### Trace Behavior

TODO: Add instrumentation if possible.

Useful metrics:

- number of traces compiled;
- number of trace aborts;
- number of side exits;
- average trace length;
- compile time;
- time spent in compiled code vs interpreter;
- number of guard failures;
- number of global/closure promotions.

This can explain why some benchmarks win and others do not.

---

## Discussion

### Why Flonum Code Wins

TODO: Explain the result in implementation terms.

Likely reasons:

- long stable loops;
- predictable operand types;
- arithmetic maps directly to machine instructions;
- generic arithmetic dispatch removed;
- branch behavior stable;
- few side exits.

### Why General Code Breaks Even

TODO: Explain without sounding defensive.

Likely reasons:

- allocation and GC dominate;
- list/pair-heavy code still calls runtime helpers;
- symbolic code has less stable type information;
- higher-order calls need better inlining;
- short benchmarks do not amortize compilation;
- current optimizer is intentionally small.

### Correctness and Dynamic Semantics

TODO:
- Explain how guards preserve dynamic behavior.
- Explain global mutation/redefinition handling.
- Explain fallback to interpreter.
- Explain unsupported features.

### Limitations

TODO: Be blunt. This helps credibility.

Possible limitations:

- only one architecture currently supported;
- limited optimization pipeline;
- limited support for continuations, if true;
- limited inlining;
- no allocation sinking, if true;
- no advanced trace scheduling;
- no mature GC integration for JIT metadata, if true;
- benchmark suite may not represent interactive Scheme workloads.

### Future Work

Possible future work:

- better higher-order call specialization;
- inlining through known closures;
- allocation sinking;
- escape analysis;
- improved side-exit trace linking;
- continuation support;
- better flonum unboxing across calls;
- typed arrays or specialized numeric vectors;
- method JIT fallback for code that traces poorly;
- improved profiler and trace visualizer.

---

## Related Work

TODO: This section needs citations later.

### Tracing JITs

Tracing JITs have been used successfully in production and research dynamic-language systems [@gal2009tracemonkey; @bolz2009pypy; @pallluajit].

Discuss:

- Dynamo;
- TraceMonkey;
- LuaJIT;
- PyPy tracing JIT;
- SELF / type feedback if relevant.

Focus comparison:

- conventional loop-header detection vs tail-call loop discovery;
- type specialization;
- guards and side exits;
- snapshots/deoptimization.

### Scheme Implementations

Chez Scheme and Gambit provide mature points of comparison for native-code Scheme implementation strategies [@dybvigchez; @feeley2007gambit].

Discuss:

- Chez Scheme;
- Gambit;
- Guile;
- Chibi;
- Larceny;
- Loko;
- Bigloo / Stalin if relevant.

Focus comparison:

- ahead-of-time or method compilation;
- native code generation;
- treatment of tail calls;
- numeric performance;
- dynamic compilation, if any.

### Dynamic Language Optimization

Possible topics:

- inline caches;
- type feedback;
- global/binding invalidation;
- closure optimization;
- unboxed numeric paths.

TODO:
- Keep related work tied to your claims.
- Do not write an encyclopedia.

---

## Conclusion

TODO: Write after evaluation.

Possible draft:

> This paper presented a tracing JIT for Scheme centered on tail-call loop discovery. By treating repeated tail calls as traceable loops and promoting stable Scheme-level facts such as global bindings, closure entrypoints, arity, and numeric representation, the system can generate efficient code for hot Scheme paths without requiring whole-program compilation. Evaluation on the R7RS benchmark suite shows that this approach is especially effective for flonum-heavy numeric programs, where speedups reach TODO, while most non-numeric programs remain near interpreter performance. These results suggest that tracing is a viable strategy for compact Scheme implementations, but that broader performance gains require deeper optimization of allocation-heavy and higher-order symbolic workloads.

TODO:
- Replace TODO with actual numbers.
- Keep claims modest and clear.

---

## Appendix A: Example Trace

TODO: Include one complete small example.

Suggested example:

```scheme
(let loop ((i 0) (x 0.0))
  (if (= i n)
      x
      (loop (+ i 1) (+ x 1.5))))
```

Show:

1. source;
2. bytecode;
3. recorded trace IR;
4. optimized trace IR;
5. rough machine-code shape;
6. guards and snapshots.

---

## Appendix B: Benchmark Harness

TODO:
- Include exact commands.
- Include build flags.
- Include benchmark runner script.
- Include raw data format.

Command placeholders:

- Hawk interpreter command.
- Hawk JIT command.
- Other implementation commands.

---

## Appendix C: Threats to Validity

TODO:
- Benchmark representativeness.
- Warmup choices.
- Hardware dependence.
- Comparison fairness across Scheme implementations.
- Implementation maturity.
- Compile time accounting.
- GC behavior.

---

## Scratch Notes / Claims to Verify

- [ ] Tail-call cycle detection is implemented as described.
- [ ] Named `let` loops are visible to the JIT as tail calls.
- [ ] Mutual tail-call loops are supported / unsupported / partially supported.
- [ ] Global promotion has correct invalidation or guard behavior.
- [ ] Closure promotion is by identity / entrypoint / layout.
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
