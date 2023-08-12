cmake_minimum_required(VERSION 3.14)

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)


# Clang is required, due to use of musttail.
set(CMAKE_C_COMPILER "clang")

project(bool VERSION 0.1)

enable_language(C)
set(CMAKE_C_STANDARD 17)

include(CheckIncludeFiles)
CHECK_INCLUDE_FILES("elf.h" HAVE_ELF)
CHECK_INCLUDE_FILES("capstone/capstone.h" HAVE_CAPSTONE)
CHECK_INCLUDE_FILES("valgrind/valgrind.h" HAVE_VALGRIND)

enable_testing()

# the JIT is optional.
option(JIT "Enable JIT" ON)

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

#set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,-readability-magic-numbers,-readability-identifier-length,-clang-analyzer-security*,-performance-no-int-to-ptr,-bugprone-easily-swappable-parameters,-readability-function-cognitive-complexity,-bugprone-sizeof-expression,-clang-analyzer-core.uninitialized.*,-clang-analyzer-core.UndefinedBinaryOperatorResult")


#set(CMAKE_C_INCLUDE_WHAT_YOU_USE "iwyu")

# PIE turned off for testing, since we JIT hot function detection is based on address of the function.
include(CheckPIESupported)
check_pie_supported()

set(SOURCES readbc.c bytecode.c vm.o  ir.c types.c symbol_table.c gc.c opcodes.h opt_loop.c parallel_copy.c)
set(SCM_SOURCES bc.scm passes.scm bootstrap.scm memory_layout.scm bc.chez.scm bc.chicken.scm util.scm str2num.scm)
set(LIBRARIES "stdc++" "m")
if (JIT) 
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DJIT")
  set(SOURCES ${SOURCES} snap.c asm_x64.c record.c emit_x64.c)
  if (HAVE_CAPSTONE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCAPSTONE")
    set(LIBRARIES ${LIBRARIES} "capstone")
  endif()
  if (HAVE_VALGRIND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVALGRIND")
  endif()
  if (HAVE_ELF)
    set(SOURCES ${SOURCES} jitdump.c)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DJITDUMP")
  endif()
endif(JIT)
if (PROFILER)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPROFILER")
  set(SOURCES ${SOURCES} profiler.cpp)
endif(PROFILER)
if (REPLAY)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DREPLAY")
  set(SOURCES ${SOURCES} replay.cpp)
endif(REPLAY)
add_library(boom_vm ${SOURCES} )

target_compile_options(boom_vm PRIVATE -gdwarf-3 -fomit-frame-pointer -fno-rtti -fno-exceptions -Wstrict-aliasing -Wdouble-promotion -Wshadow -Wno-unused-parameter -Wnull-dereference )
set_property(TARGET boom_vm PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_include_directories(boom_vm PUBLIC ".")

target_link_libraries(boom_vm PUBLIC ${LIBRARIES}  )

# Use the CC10 calling convention, which isn't available via clang, but is in llvm.
# munge win64cc to cc10.
# Otherwise we could include vm.c directly.
add_library(vm OBJECT EXCLUDE_FROM_ALL vm.c opcodes.h)
target_compile_options(vm PRIVATE -emit-llvm -S )
set_property(TARGET vm PROPERTY POSITION_INDEPENDENT_CODE TRUE)
get_target_property(BOOM_FLAGS boom_vm COMPILE_OPTIONS)
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
list(REMOVE_ITEM CLOC_SOURCES bootstrap.c)
add_custom_target(
  cloc
  COMMAND cloc --by-file-by-lang ${SCM_SOURCES} ${CLOC_SOURCES} 
)

add_custom_target(
  format
  COMMAND clang-format -i *.h *.c
  )

# Generate the bootstrap image.
add_custom_command(
  OUTPUT  bootstrap.scm.bc bootstrap.c
  COMMAND
  mkdir -p third-party
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/bc.chez.scm ${CMAKE_SOURCE_DIR}/bc.scm ${CMAKE_SOURCE_DIR}/memory_layout.scm ${CMAKE_SOURCE_DIR}/passes.scm ${CMAKE_SOURCE_DIR}/bootstrap.scm ${CMAKE_SOURCE_DIR}/str2num.scm .
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/third-party/alexpander.scm third-party/.
  COMMAND
  ${CHEZ} --script bc.chez.scm bootstrap.scm > /dev/null
  COMMAND
  xxd -i bootstrap.scm.bc > bootstrap.c
  DEPENDS ${SCM_SOURCES} opcodes.scm
)

# Generate the opcodes
add_custom_command(
  OUTPUT opcodes.c opcodes.h opcodes-table.h opcodes.scm
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/opcode_gen.scm ${CMAKE_SOURCE_DIR}/util.scm .
  COMMAND
  ${CHEZ} --script opcode_gen.scm
  DEPENDS util.scm opcode_gen.scm vm.c
)

# Actual executable
add_executable(boom  bootstrap.c boom.c)
target_link_libraries(boom PUBLIC boom_vm)
set_property(TARGET boom PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)


# Tests
add_test(NAME r5rs_pitfall COMMAND ./boom --joff test/r5rs_pitfall.scm)
set_tests_properties(r5rs_pitfall PROPERTIES FAIL_REGULAR_EXPRESSION "Failure")
add_test(NAME r5rs_tests COMMAND ./boom --joff test/r5rs-tests.scm )
set_tests_properties(r5rs_tests PROPERTIES PASS_REGULAR_EXPRESSION "175 out of 176 passed")
add_test(NAME r4rs_test COMMAND ./boom --joff test/r4rstest.scm )
set_tests_properties(r4rs_test PROPERTIES PASS_REGULAR_EXPRESSION "Passed all tests")

add_test(NAME fib COMMAND ./boom test/fib.scm )
set_tests_properties(fib PROPERTIES PASS_REGULAR_EXPRESSION "102334155")
add_test(NAME ack COMMAND ./boom test/ack.scm )
set_tests_properties(ack PROPERTIES PASS_REGULAR_EXPRESSION "32765")
add_test(NAME tak COMMAND ./boom test/tak.scm )
set_tests_properties(tak PROPERTIES PASS_REGULAR_EXPRESSION "12")
add_test(NAME sum COMMAND ./boom test/sum.scm )
set_tests_properties(sum PROPERTIES PASS_REGULAR_EXPRESSION "500000000500000000")

# Benches
add_test(NAME bench/tak COMMAND ./boom test/bench/tak.scm )
set_tests_properties(bench/tak PROPERTIES PASS_REGULAR_EXPRESSION "18")
add_test(NAME bench/ack COMMAND ./boom test/bench/ack.scm )
set_tests_properties(bench/ack PROPERTIES PASS_REGULAR_EXPRESSION "4093")
add_test(NAME bench/fib COMMAND ./boom test/bench/fib.scm )
set_tests_properties(bench/fib PROPERTIES PASS_REGULAR_EXPRESSION "9227465")
add_test(NAME bench/sum COMMAND ./boom test/bench/sum.scm )
set_tests_properties(bench/sum PROPERTIES PASS_REGULAR_EXPRESSION "5000050000")
add_test(NAME bench/sumloop COMMAND ./boom test/bench/sumloop.scm )
set_tests_properties(bench/sumloop PROPERTIES PASS_REGULAR_EXPRESSION "1000000000")

add_test(NAME bench/diviter COMMAND ./boom --heap-sz=1000000 test/bench/diviter.scm )
set_tests_properties(bench/diviter PROPERTIES PASS_REGULAR_EXPRESSION "50000000")

add_test(NAME bench/divrec COMMAND ./boom --heap-sz=100000 test/bench/divrec.scm )
set_tests_properties(bench/divrec PROPERTIES PASS_REGULAR_EXPRESSION "5000000")

add_test(NAME bench/cat COMMAND ./boom  test/bench/cat.scm )
set_tests_properties(bench/cat PROPERTIES PASS_REGULAR_EXPRESSION "END")
add_test(NAME bench/cpstak COMMAND ./boom  test/bench/cpstak.scm )
set_tests_properties(bench/cpstak PROPERTIES PASS_REGULAR_EXPRESSION "RESULT: 9")
