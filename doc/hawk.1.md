HAWK 1 "September 2023" Linux "User Manuals"
============================================

NAME
----

hawk - scheme (r5rs) jit

SYNOPSIS
--------

`hawk` [options] *file.[scm|bc]* ...

WEB SITE
--------

https://github.com/djwatson/hawk


DESCRIPTION
-----------

`hawk` is a vm (virtual machine) and jit compiler (just-in-time) for the scheme
language, report version r5rs.  It can run scripts directly, or pre-compile them
to an executable.


OPTIONS
-------

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
  statistics gathered are printed to stdout.

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

EXAMPLES
--------

  ./hawk hello.scm

Prints 'hello world', assuming hello.scm contains

  (display "hello world")

Compile the hello.scm script to an executable:

  ./hawk --exe hello.scm
  ./hello


COPYRIGHT
---------

`hawk` is Copyright c 2023 Dave Watson.
`hawk` is open source software, released under the MIT license.

AUTHOR
------

Dave Watson <dade.watson@gmail.com>

SEE ALSO
--------

