# Required dependencies:

* clang 8+, for musttail
* A scheme for bootstraping, currently chez (and chicken) are supported.

# Usefull cmake install variables:

* -DCMAKE_BUILD_TYPE=RELEASE (or RelWithDebugInfo or Debug)
* -DJIT=on                        JIT.  Currently only works on x86_64 posix (macos/linux)
* -DPROFILER=off                  A sampling profiler, currently only supported on linux.
* -DCMAKE_UNITY_BUILD=false       Build a 'unity' build, which should be similar to LTO.
* -DBUILD_SHARED_LIBS=false       Probably want to build twice with shared and not shared for a real install.
* -DCMAKE_INSTALL_PREFIX=

# Auto-checked dependencies:

* LTO is turned on if possible.
* Capstone is linked for debug listing if available.
* Valgrind support is added if headers are found.
* jitdump support is added if elf.h is found
