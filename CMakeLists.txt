cmake_minimum_required(VERSION 3.14)

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

set(CMAKE_C_FLAGS_ASAN
        "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Build with AddressSanitizer"
        FORCE)
set(CMAKE_C_FLAGS_LSAN
        "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Build with LeakSanitizer"
        FORCE)
 
    set(CMAKE_CXX_FLAGS_TSAN
        "-fsanitize=thread -g -O1"
        CACHE STRING "Build with ThreadSanitizer"
        FORCE)
 
    set(CMAKE_C_FLAGS_MSAN
        "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
        CACHE STRING "Build with MemorySanitizer"
        FORCE)
 
    set(CMAKE_C_FLAGS_UBSAN
        "-fsanitize=undefined"
        CACHE STRING "Build with UndefinedBehaviourSanitizer"
        FORCE)      
      

project(bool VERSION 0.1)

enable_language(C)
set(CMAKE_C_STANDARD 17)

# Clang is required, due to use of musttail.
if(NOT CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER "clang")
endif()
get_filename_component(COMP_BASENAME ${CMAKE_C_COMPILER} NAME)
if (NOT ${COMP_BASENAME} STREQUAL "clang")
  message("WARNING: [[musttail]] attribute only supported on clang.  VM might cause stack overflows!")
endif()  

include(CheckIncludeFiles)
CHECK_INCLUDE_FILES("elf.h" HAVE_ELF)
CHECK_INCLUDE_FILES("capstone/capstone.h" HAVE_CAPSTONE)

enable_testing()

# VALGRIND is optional.
option(VALGRIND "Enable VALGRIND" OFF)

# the JIT is optional.
option(JIT "Enable JIT" ON)

# the profiler is optional
option(PROFILER "Enable PROFILER" OFF)

# Find a suitable scheme for bootstrapping.
# Chez and chicken have been tested, it's likely most r5rs (+ write-u8) compatible
# schemes will work with minor changes.
find_program(CHEZ chez)
if (NOT CHEZ)
  find_program(CHEZ chezscheme)
  if (NOT CHEZ)
    message(FATAL_ERROR "Can't find chez scheme for bootstrapping")
  endif()
endif()
message("Using " ${CHEZ} " for bootstrapping")

#set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,-readability-magic-numbers,-readability-identifier-length,-clang-analyzer-security*,-performance-no-int-to-ptr,-bugprone-easily-swappable-parameters,-readability-function-cognitive-complexity,-bugprone-sizeof-expression,-clang-analyzer-core.uninitialized.*,-clang-analyzer-core.UndefinedBinaryOperatorResult")


#set(CMAKE_C_INCLUDE_WHAT_YOU_USE "iwyu")

# PIE turned off for testing, since we JIT hot function detection is based on address of the function.
include(CheckPIESupported)
check_pie_supported()


add_subdirectory(src)
add_subdirectory(test)

#install
install(TARGETS hawk_vm hawk hawk_exe)
INSTALL(FILES doc/hawk.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)

set(CPACK_PACKAGE_NAME hawk)
set(CPACK_PACKAGE_CONTACT "Dave Watson <dade.watson@gmail.com>")
set(CPACK_GENERATOR DEB)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "clang, libcapstone-dev")
include(CPack)
