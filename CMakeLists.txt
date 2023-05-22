cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Clang is required, due to use of musttail.
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang")

project(bool VERSION 0.1)

enable_language(C)

enable_testing()

# the JIT is optional.
option(JIT "Enable JIT" OFF)

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

#set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-fix;-checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,-readability-magic-numbers")
#set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "iwyu")

# PIE turned off for testing, since we JIT hot function detection is based on address of the function.
include(CheckPIESupported)
check_pie_supported()

# -Wold-style-cast
set(CMAKE_CXX_FLAGS "-O3 -fomit-frame-pointer -gdwarf-3 -Wall -Wextra -Wno-unused-parameter  -Wnull-dereference   -Wdouble-promotion -Wshadow -Wformat=2 -fno-strict-aliasing -flto -fvisibility=hidden")
set(SOURCES readbc.cpp bytecode.cpp vm.o boom.cpp  ir.cpp types.cpp bootstrap.cpp symbol_table.cpp gc.cpp opcodes.h)
set(SCM_SOURCES bc.scm passes.scm bootstrap.scm memory_layout.scm bc.chez.scm bc.chicken.scm util.scm)
set(LIBRARIES "stdc++" "m")
if (JIT) 
  set(SOURCES ${SOURCES} snap.cpp replay.cpp asm_x64.cpp jitdump.cpp record.cpp)
  set(LIBRARIES ${LIBRARIES} "asmjit" "capstone")
endif(JIT)
add_executable(boom ${SOURCES} )


set_property(TARGET boom PROPERTY POSITION_INDEPENDENT_CODE FALSE)
target_include_directories(boom PUBLIC ".")

target_link_libraries(boom PUBLIC ${LIBRARIES}  )

# Use the CC10 calling convention, which isn't available via clang, but is in llvm.
# munge win64cc to cc10.
string(REPLACE " " ";" LLVM_FLAGS ${CMAKE_CXX_FLAGS})
add_custom_command(
  OUTPUT vm.o
  COMMAND
  clang -S -emit-llvm -c vm.cpp ${LLVM_FLAGS}
  COMMAND
  mv vm.s vm.ll
  COMMAND
  perl -p -i -e 's/win64cc/cc10/g' vm.ll
  COMMAND
  clang -gdwarf-3 ${LLVM_FLAGS} -c vm.ll
  DEPENDS vm.cpp opcodes.h
  )

add_custom_target(
  cloc
  COMMAND cloc --by-file-by-lang ${SCM_SOURCES} *.h ${SOURCES} vm.cpp
)

add_custom_target(
  format
  COMMAND clang-format -i *.h *.cpp
  )

add_library(write_double SHARED write_double.c)

# Generate the bootstrap image.
add_custom_command(
  OUTPUT  bootstrap.scm.bc bootstrap.cpp
  COMMAND
  ${CHEZ} --script bc.chez.scm bootstrap.scm > /dev/null
  COMMAND
  xxd -i bootstrap.scm.bc > bootstrap.cpp
  DEPENDS ${SCM_SOURCES} write_double opcodes.scm 
)

# Generate the opcodes
add_custom_command(
  OUTPUT opcodes.cpp opcodes.h opcodes-table.h opcodes.scm
  COMMAND
  ${CHEZ} --script opcode_gen.scm
  DEPENDS util.scm opcode_gen.scm
)
