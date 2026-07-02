# Hawk

Hawk is a tracing JIT compiler for Scheme.  It includes a bytecode
compiler, runtime, garbage collector, interpreter, trace recorder, and native
code emitters for x86-64 and aarch64.

Hawk is free software released under the MIT license.  See `LICENSE` for
details.

## Requirements

To build Hawk from a release tarball:

- CMake 3.20 or newer
- a C23 compiler
- zstd (optional, for compressed heap images)
- capstone (optional, for disassembly output)
- normal build tools such as `make` or `ninja`

To build directly from Git, or to make a release tarball, you also need:

- Gauche Scheme (`gosh`) to bootstrap the Scheme image

To build the paper during `dist`, you also need:

- Python 3
- matplotlib
- pandoc
- pdflatex

## Release Build

Release tarballs include `boot/img.scm.bc`, the prebuilt Scheme bootstrap
image.  This is the recommended path for users who only want to build and run
Hawk.

```sh
tar xf hawk-VERSION.tar.gz
cd hawk-VERSION
cmake -S . -B build
cmake --build build
```

No Scheme implementation is needed for this path.  The default
`-DBOOTSTRAP=OFF` build embeds the included `boot/img.scm.bc` into the `hawk`
executable.

Install with:

```sh
cmake --install build
```

Use `--prefix` at configure time to choose an install prefix:

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build
cmake --install build
```

## Git Build

Git checkouts do not include `boot/img.scm.bc`.  Build with
`-DBOOTSTRAP=ON` so the build first creates a bootstrap-capable `hawk`, uses
Gauche to compile the Scheme sources, then writes `boot/img.scm.bc`.

```sh
git clone https://github.com/djwatson/hawk.git
cd hawk
cmake -S . -B build -DBOOTSTRAP=ON
cmake --build build
```

## Release Tarballs

The `dist` target creates a source release tarball from exactly the Git-tracked
files, plus generated release artifacts:

- `boot/img.scm.bc`
- `hawk-paper.pdf`

Run it from any configured build tree:

```sh
cmake --build build --target dist
```

The output is:

```text
build/hawk-VERSION.tar.gz
```

`VERSION` defaults to `git describe --tags --always --dirty`.  Override it at
configure time with:

```sh
cmake -S . -B build -DHAWK_DIST_VERSION=0.7.0
cmake --build build --target dist
```

If `dist` is run from a non-bootstrap build tree, it creates an internal
bootstrap build only to generate `boot/img.scm.bc`.

## Tests

Build and run the test suite with:

```sh
cmake --build build
cd build
ctest -j
```

## Cross Compilation

An aarch64 toolchain file is included:

```sh
cmake -S . -B build_aarch64 -DCMAKE_TOOLCHAIN_FILE=aarch64.cmake
cmake --build build_aarch64
```

The build creates a small host-side code generator when cross compiling.

## Usage

Run a Scheme file:

```sh
./build/hawk hello.scm
```

Run with the JIT disabled:

```sh
./build/hawk --joff hello.scm
```

Useful options include:

- `--joff`: run only the bytecode VM
- `-i, --image PATH`: load an explicit `.bc` image file
- `-D NAME`: add a Scheme feature before loading a script
- `-I DIRECTORY`: prepend a directory to the Scheme library search path
- `-A DIRECTORY`: append a directory to the Scheme library search path
- `--list`: compile the script and list bytecode without running it
- `--exe`: build an executable from a `.scm` source file
- `-m, --max-trace NUMBER`: stop JIT compilation after a trace count
- `-d, --dump`: emit debugging information for tools such as gdb and perf
- `-p, --profile`: turn on the sampling profiler
- `-v, --verbose`: print tracing, IR, machine code, and GC information
- `--version`: print the version
- `-h, --help`: show command line help

`--exe` writes `FILE.hawk-image.c` and `FILE.hawk-image.bc` next to
`FILE.scm`, then links `FILE` against `libhawk_core` using the system linker.
Install Hawk first, or set the usual compiler and loader search paths such as
`LIBRARY_PATH` and `LD_LIBRARY_PATH`, so `-lhawk_core` can be found.

## Platform Notes

Hawk currently has native emitters for x86-64 and aarch64.  It is developed on
Linux and macOS.  The runtime is written in C23 with a small amount of
architecture-specific code for machine-code emission.

It has been tested and known to work on
linux x86_64
osx aarch64
linux qemu usermode aarch64
