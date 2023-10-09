Tips for Hacking on Hawk
========================

How the build works
-------------------

# opcode_gen.scm

We scan vm.c with opcode_gen.scm, and generate the opcode map.  This
map is shared between the SCM and C code, so it can't be a C X macro.
Lines starting with LIBRARY_FUNC are considered opcodes, and the first
argument is taken as the name.  The rest of the macro only applies to
the C code currently.

# Bootstrap

`Bootstrap` is the name of the SCM code that makes up the majority of
the standard library.  Currently chez, chicken, or hawk itself may be
used to compile the bootstrap.scm, bc.scm, alexpander.scm, and various
support .scm files to bytecode.  The bytecode is then converted to a C
array using xxd -i.  Currently everything compiled must be in a single
file, or '(include ...)'ed from a single file (recursively).
I.e. there is no seperate module compilation support (yet...).

# VM

The rest of the VM and JIT can then be built in to libhawk_vm.  It can
be either a static or dynamic library based on CMAKE config options.
The main entry point is run(...).  There are also various config
options possible.

# Main

There are two executables generated: hawk, and libhawk_exe.  The
latter is used for the --exe option, so end user scripts can be made
in to executable files easily.  It's also quite possible to use
libhawk_vm directly, but it's under-documented.  It's even possible to
drop the standard library completely, for an extremely small runtime.

Debugging
---------

CMAKE_BUILD_TYPE can be set to Debug to get the assert()s working and
get debug info.  There are a couple commented out lines in
CMakeLists.txt, that can be used to enable -fsanitize=address
support.  Valgrind can also be used, since sanitizers won't cover the
JITed code, but valgrind will.  Note that gdb's jit support is O(n) in
the number of jit traces - consider using --max-trace to limit it.

ASAN,LSAN,TSAN,MSAN,UBSAN can be turned on by specifying -DCMAKE_BUILD_TYPE=ASAN, etc.

The traces fire based on the address of a malloc'd codeblock - so
consider disabling PIE, or even hardcoding constants to get consistent
traces.

GC debugging is always painful - however there are a couple mmap
statements that should be useful in detecting uses that missed being
traced.

Linting
-------

CLANG_TIDY, IWYU, CPPCHECK, CPPLINT have 'set' statements in the main
CMakeFiles.txt that can be enabled.  There are also comments
explaining how to use oclint. 

S7 scheme has a great scheme linter, usable something like:

```
./s7
(load "s7/lint.scm")
(lint "bc.scm")
```


Profiling
---------

Linux PERF tool is available with the --dump option.   Make sure you
have an up-to-date perf tool (as of this writing the version in Ubuntu
stable is too old) for perf-inject support.  See the hawk_record and
hawk_report scripts for examples of usage.

There is an experimental profiler for the bytecode available with
--profile.  It fires a signal on a timer, and grabs the stack.  At the
end of the script, it symbolizes the functions and prints them by call
frequency.   Currently it does not support the jited code.

BYTECODE VM
-----------

The bytecode is extremely similar in style to luajit - an opcode, a
destination register, and either two operand registers or a U16 sized
operand, used for either relative jumps, or the global table.

Currently functions (bcfunc's) are not stored in the heap, and never
freed.  You can load as many scripts as you want, until you run out of
memory, or run out of constant storage - limited to the U16 size
(65536).  None of the current scripts, including 'compiler.scm', come
anywhere close to this, since constants are uniq'd per script.

Unlike Luajit, the VM is not written in assembly, but uses tailcalls
to jump to the next instruction.  This gives ~95% of the performance
of the Luajit VM, while being much more portable.  Most of the last
bits of performance are the lack of being able to use callee-save
registers without saving them.   Something like 'cc10' calling
convention in LLVM would fix most of this, but isn't available to
clang currently, only llvm.  There was some experimental support for
generating LLVM and modifying this directly, it was a bit hacky.

There are several passes in the frontend for assignment conversion and
closure conversion, but also, LOOP detection - it's somewhat important
to detect loops statically if possible.  The trace recorder uses the
fact that this is a known loop to create better traces.

JIT
---

The JIT is also extremely similar to LuaJIT, but modified for scheme
semantics.

The trace recorder starts recording on function calls and loops.
There are several types of traces: Loop traces, up-recursive traces,
and down-recursive traces, and finally, simple traces through a
function.  The last is the least-desirable, since it doesn't form a
loop.   Additionally, side-traces can connect any of these traces
to each other.

Traces begin by putting appropriate variables from the scheme stack to
register slots, and vice versa on return, and potentially adjusting
the scheme stack to account for inlined calls.   Note this is
different than LuaJIT - LJ traces assume all data starts in the stack,
while hawk will proactively move data to registers to start:  This is
important for looping traces (either tail-recursive or a LOOP), where
variables will stay in registers, instead of being flushed to the
stack.  This is *very* important for scheme, where recursion & tail
recursion are more common.  Conversely, LJ relies on the `opt_loop`
pass to move things to registers.

TODOs
-----

There's a long list, but major work includes:

* bigint / complex support
* faster call/cc using a strategy like chez
* r7rs / modules / a more modern macro expander
* Put all functions and constants in the heap, so we never run out and
  can free them.  This would allow ... 
* A full repl and not just per-script.
* More tests.
* aarch64 support.
* FLONUM support in the JIT.
* Various missing NYI's in the jit.
* Move more of the standard library to C as apporpriate - in partiular
  member/assoc and friends, and read / number->string / string->number,
  string-append, substring are prime candidates.


