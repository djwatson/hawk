cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

# Clang is required, due to use of musttail.
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang")

project(bool VERSION 0.1)

enable_language(C)
set(CMAKE_C_STANDARD 17)

enable_testing()

# the JIT is optional.
option(JIT "Enable JIT" OFF)

# the profiler is optional
option(PROFILER "Enable PROFILER" OFF)

# enable the replay IR test framework
option(REPLAY "Enable REPLAY test framework" OFF)

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
#set(CMAKE_C_CLANG_TIDY "clang-tidy;-fix;-checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,-readability-magic-numbers")


#set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "iwyu")
#set(CMAKE_C_INCLUDE_WHAT_YOU_USE "iwyu")

# PIE turned off for testing, since we JIT hot function detection is based on address of the function.
include(CheckPIESupported)
check_pie_supported()

set(SOURCES readbc.c bytecode.c vm.o boom.cpp  ir.cpp types.c bootstrap.cpp symbol_table.c gc.c opcodes.h profiler.cpp opt_loop.c parallel_copy.c)
set(SCM_SOURCES bc.scm passes.scm bootstrap.scm memory_layout.scm bc.chez.scm bc.chicken.scm util.scm str2num.scm)
set(LIBRARIES "stdc++" "m")
if (JIT) 
  set(SOURCES ${SOURCES} snap.c asm_x64.cpp jitdump.c record.cpp emit_x64.c)
  set(LIBRARIES ${LIBRARIES} "capstone")
endif(JIT)
if (PROFILER)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPROFILER")
endif(PROFILER)
if (REPLAY)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DREPLAY")
  set(SOURCES ${SOURCES} replay.cpp)
endif(REPLAY)
add_executable(boom ${SOURCES} )

target_compile_options(boom PRIVATE -fomit-frame-pointer -fno-rtti -fno-exceptions -Wstrict-aliasing -Wdouble-promotion -Wshadow
  -Wno-unused-parameter -Wnull-dereference )
set_property(TARGET boom PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

set_property(TARGET boom PROPERTY POSITION_INDEPENDENT_CODE FALSE)
target_include_directories(boom PUBLIC ".")

target_link_libraries(boom PUBLIC ${LIBRARIES}  )

# Use the CC10 calling convention, which isn't available via clang, but is in llvm.
# munge win64cc to cc10.
# Otherwise we could include vm.c directly.
add_library(vm OBJECT EXCLUDE_FROM_ALL vm.c opcodes.h)
target_compile_options(vm PRIVATE -emit-llvm -S )
get_target_property(BOOM_FLAGS boom COMPILE_OPTIONS)
target_compile_options(vm PRIVATE ${BOOM_FLAGS} )
string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UPPER)
set(VM_FLAGS  ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}})
string(REPLACE " " ";" VM_FLAGS ${VM_FLAGS})
target_compile_options(vm PRIVATE -fomit-frame-pointer) # required for cc10
  add_custom_command(
  OUTPUT vm.o
  COMMAND
  cp $<TARGET_OBJECTS:vm> vm.ll
  COMMAND
  perl -p -i -e 's/win64cc/cc10/g' vm.ll
  COMMAND
  clang ${BOOM_FLAGS} ${VM_FLAGS}  -c vm.ll -flto=thin
  DEPENDS vm.c vm
  )


#target_compile_options(boom PRIVATE -fsanitize=address,undefined)
#target_link_options(boom PRIVATE -fsanitize=address,undefined)
#target_compile_options(vm PRIVATE -fsanitize=address,undefined)

set(CLOC_SOURCES ${SOURCES} vm.c)
list(REMOVE_ITEM CLOC_SOURCES bootstrap.cpp)
add_custom_target(
  cloc
  COMMAND cloc --by-file-by-lang ${SCM_SOURCES} ${CLOC_SOURCES} 
)

add_custom_target(
  format
  COMMAND clang-format -i *.h *.cpp
  )

add_library(write_double SHARED EXCLUDE_FROM_ALL write_double.c)

# Generate the bootstrap image.
add_custom_command(
  OUTPUT  bootstrap.scm.bc bootstrap.cpp
  COMMAND
  mkdir -p third-party
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/bc.chez.scm ${CMAKE_SOURCE_DIR}/bc.scm ${CMAKE_SOURCE_DIR}/memory_layout.scm ${CMAKE_SOURCE_DIR}/passes.scm ${CMAKE_SOURCE_DIR}/bootstrap.scm ${CMAKE_SOURCE_DIR}/str2num.scm .
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/third-party/alexpander.scm third-party/.
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
  rsync ${CMAKE_SOURCE_DIR}/opcode_gen.scm ${CMAKE_SOURCE_DIR}/util.scm .
  COMMAND
  ${CHEZ} --script opcode_gen.scm
  DEPENDS util.scm opcode_gen.scm vm.c
)
