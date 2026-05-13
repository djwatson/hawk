---
title: Intro
permalink: /
---

# Hawk

<p class="lede">A small Scheme VM and tracing JIT compiler.</p>

Hawk targets Scheme with a compact runtime, bytecode compiler, tracing recorder, and native code backends. The project is written in C23 and Scheme

## Overview

- Tracing JIT compiler implementing [R7RS Scheme](https://small.r7rs.org/).
- Native code generation for x86_64 and aarch64.
- MIT licensed under the [MIT License](https://opensource.org/license/mit).
- Source on [GitHub](https://github.com/djwatson/hawk).

## JIT

Hawk is an experimental tracing JIT, pushing tracing to its limits on
a functional language.  Much inspiration was taken from [LuaJIT](https://luajit.org/).

Hawk supports advanced tracing JIT features like:

- unboxing flonums to registers
- promoting globals to constants
- promoting closures to constants
- Splitting of polymorphic functions.
- lazy typechecking.  Types are only checked when required.
- tracing of all scheme code, including call/cc.

As well as more standard compiler features, like:

- SSA form
- constant propagation
- CSE (constant subexpression elimination)
- DCE (dead code elimination)
- turning tailcalled functions back in to loops when appropriate
