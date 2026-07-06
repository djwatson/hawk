---
title: Releases
permalink: /releases/
---

# Releases

## v0.9

Hawk v0.9 is the first public source release. It includes:

- a tracing JIT compiler for Scheme
- bytecode compiler, VM, runtime, garbage collector, and native emitters
- x86-64 and aarch64 support
- release tarballs with a pregenerated boot image, so Gauche is not needed for normal release builds

```sh
tar xf hawk-v0.9.tar.gz
cd hawk-v0.9
cmake -S . -B build
cmake --build build
./build/hawk --version
```
