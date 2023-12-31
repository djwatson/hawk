cmake_minimum_required(VERSION 3.14)

if(NOT CMAKE_C_COMPILER)
  if (NOT DEFINED ENV{CC})
    find_program(CLANG_CC clang)
    if (CLANG_CC) 
      set(CMAKE_C_COMPILER "clang")
    endif()
  endif()
endif()

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
      

#set(CMAKE_C_CLANG_TIDY "clang-tidy")
#set(CMAKE_C_INCLUDE_WHAT_YOU_USE "iwyu")
#set(CMAKE_C_CPPCHECK "cppcheck" "--enable=warning,style,performance,portability,information" "--std=c11")
#set(CMAKE_C_CPPLINT "cpplint")
# OClint settings:
# cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
# ~/projects/oclint/oclint-22.02/bin/oclint -p .  -rc SHORT_VARIABLE_NAME=1 src/*.c

project(bool VERSION 0.1)


enable_language(C)
set(CMAKE_C_STANDARD 17)

enable_language(ASM)

# Clang is required, due to use of musttail.
if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
  message("WARNING: [[musttail]] attribute only supported on clang.  VM might cause stack overflows! ${CMAKE_C_COMPILER_ID}")
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
