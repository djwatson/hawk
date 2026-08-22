---
title: Releases
permalink: /releases/
---

# Releases

## v0.10

Hawk v0.10 is the latest release. It includes:

- faster stack limit checks and VM stack scanning
- operand and constant fusion for more efficient generated code
- improved x86-64 and aarch64 code emitters
- optimized integer hashing and `assv`
- the `--unsafe` option for disabling array bounds checks
- Arch Linux and Debian package support

[Download the v0.10 source tarball](https://github.com/djwatson/hawk/releases/download/v0.10/hawk-v0.10.tar.gz).

```sh
tar xf hawk-v0.10.tar.gz
cd hawk-v0.10
cmake -S . -B build
cmake --build build
./build/hawk --version
```

## v0.9

Hawk v0.9 is the first public source release. It includes:

- a tracing JIT compiler for Scheme
- bytecode compiler, VM, runtime, garbage collector, and native emitters
- x86-64 and aarch64 support
- release tarballs with a pregenerated boot image, so Gauche is not needed for normal release builds

[Download the v0.9 source tarball](https://github.com/djwatson/hawk/releases/download/v0.9/hawk-v0.9.tar.gz).

```sh
tar xf hawk-v0.9.tar.gz
cd hawk-v0.9
cmake -S . -B build
cmake --build build
./build/hawk --version
```
