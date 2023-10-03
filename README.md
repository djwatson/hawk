[![test](https://github.com/djwatson/hawk/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/djwatson/hawk/actions/workflows/test.yml)

`Hawk` is a Just-In-Time (JIT) compiler for the Scheme programming language.

Hawk is Copyright (C) 2023 Dave Watson.
Hawk is free software, released under the MIT license.
See full Copyright Notice in the LICENSE file.

See the doc/ folder for additional documentation.


## WEB SITE

https://djwatson.github.io/hawk

## BUILDING

Hawk has no dependencies other than a recent (> 13) clang.  GCC
(tested 11.4.0) is known to correctly compile all tail calls in
Release mode, but not in Debug mode.

It has an optional dependency on libcapstone, and elf headers for debugging.
Currently chezscheme or chicken is used for bootstrapping, but is not
used after install.

```
sudo apt install chezscheme
git clone https://github.com/djwatson/hawk.git
cd hawk
cmake .
make -j
sudo make install
```

## OPTIONS

`--joff`
  Turn off the jit compiler, only use the bytecode VM.

`-m, --max-trace`  *NUMBER* 
  Only trace up to *NUMBER* traces, and then only interpret.

`--dump`
  Turn on debugging dumps for gdb and linux perf tool.

`-l, --list`
  Compile the script and dump the resulting code in human-readable
  format to stdout, and then quit.

`-p, --profile`
  Turn on the bytecode profiler.  After the script finishes,
  statistics gathered are printed to stdout.  Requires building with
  -DJIT=on

`--exe`
  Compile the script in to an exe by linking it with libhawk_exe.
  Note that this is no faster than running a `.bc` file directly
  with hawk, and is only a convenience.  Script is only compiled
  and not run.

`-v, --verbose`
  Turn on verbosity.  Prints tracing info, generated trace IR, and
  machine code.  Also displays GC collection info.

`-h, --help`
  Print help message and exit.

## EXAMPLES
```
hawk hello.scm
```
Prints 'hello world', assuming hello.scm contains
```
(display "hello world")
```
Compile the hello.scm script to an executable:
```
hawk --exe hello.scm
./hello
```

# Standards

Currently hawk is closest to the r4rs standard, with the following
restrictions:

*  Symbols starting with '$' are reserved
*  Bignums / complex / ratios are unimplemented, only fixnum
      overflowing to flownum are supported.
*  syntax-rules cannot be defined in one file, and used in another.
*  Modules are not implemented, including the builtin library:
      While you can redefine most builtin procedures (assuming
      integration is turned off), many library functions still call
      these procedures through the global table.  E.g. if you redefine
      'car', 'caar' will call the new procedure twice.
*  The lexer is r7rs compliant.
*  No unicode, all strings are ascii-only.
*  Bytevectors are just defined to be strings.

And jit restrictions:

*  x86_64 / sysv only.  Known to work on linux & osx intel.
*  flonums are unimplemented in the jit.
*  Most file operations fallback to VM.
