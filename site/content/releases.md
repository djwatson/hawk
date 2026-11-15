---
title: Releases
permalink: /releases/
---

# Releases

## v0.13

Hawk v0.13 is the latest release. It includes:

- JIT loop and integer range optimizations
- bytecode liveness analysis and improved address indexing
- variable nursery sizing and faster allocation
- faster ASCII strings, symbol reading, and number parsing
- specialized `string-append`, vector construction, and `memq` paths

[Download the v0.13 source tarball](https://github.com/djwatson/hawk/releases/download/v0.13/hawk-v0.13.tar.gz),
[Debian amd64 package](https://github.com/djwatson/hawk/releases/download/v0.13/hawk_0.13_amd64.deb),
or [Arch Linux PKGBUILD](https://github.com/djwatson/hawk/releases/download/v0.13/PKGBUILD).

```sh
tar xf hawk-v0.13.tar.gz
cd hawk-v0.13
cmake -S . -B build
cmake --build build
./build/hawk --version
```

## v0.12

Hawk v0.12 includes:

- Unicode strings, characters, case conversion, and UTF-8 input/output
- JIT recording for `apply`
- improved operand scheduling and register allocation
- faster inexact complex-number allocation
- numeric, reader, runtime, and garbage-collection fixes

[Download the v0.12 source tarball](https://github.com/djwatson/hawk/releases/download/v0.12/hawk-v0.12.tar.gz),
[Debian amd64 package](https://github.com/djwatson/hawk/releases/download/v0.12/hawk_0.12_amd64.deb),
or [Arch Linux PKGBUILD](https://github.com/djwatson/hawk/releases/download/v0.12/PKGBUILD).

```sh
tar xf hawk-v0.12.tar.gz
cd hawk-v0.12
cmake -S . -B build
cmake --build build
./build/hawk --version
```

## v0.11

Hawk v0.11 It includes an improved garbage collector.

[Download the v0.11 source tarball](https://github.com/djwatson/hawk/releases/download/v0.11/hawk-v0.11.tar.gz).

```sh
tar xf hawk-v0.11.tar.gz
cd hawk-v0.11
cmake -S . -B build
cmake --build build
./build/hawk --version
```

## v0.10

Hawk v0.10 It includes:

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
