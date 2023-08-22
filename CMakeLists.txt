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

set(SOURCES readbc.c bytecode.c vm.c bootstrap.c ir.c types.c symbol_table.c gc.c opcodes.h opt_loop.c parallel_copy.c)
set(SCM_SOURCES bc.scm passes.scm bootstrap.scm memory_layout.scm bc.chez.scm bc.chicken.scm util.scm str2num.scm)
set(LIBRARIES "m")
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

#target_compile_options(boom PRIVATE -fsanitize=address,undefined)
#target_link_options(boom PRIVATE -fsanitize=address,undefined)
#target_compile_options(vm PRIVATE -fsanitize=address,undefined)

set(CLOC_SOURCES ${SOURCES} boom.c)
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
add_executable(boom  boom.c)
target_link_libraries(boom PUBLIC boom_vm)
set_property(TARGET boom PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)


# Tests
add_test(NAME r5rs_pitfall COMMAND ./boom test/r5rs_pitfall.scm)
set_tests_properties(r5rs_pitfall PROPERTIES FAIL_REGULAR_EXPRESSION "Failure")
add_test(NAME r5rs_tests COMMAND ./boom  test/r5rs-tests.scm )
set_tests_properties(r5rs_tests PROPERTIES PASS_REGULAR_EXPRESSION "175 out of 176 passed")
add_test(NAME r4rs_test COMMAND ./boom test/r4rstest.scm )
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
add_test(NAME bench/sumfp COMMAND ./boom test/bench/sumfp.scm )
set_tests_properties(bench/sumfp PROPERTIES PASS_REGULAR_EXPRESSION "#t")
add_test(NAME bench/fibfp COMMAND ./boom test/bench/fibfp.scm )
set_tests_properties(bench/fibfp PROPERTIES PASS_REGULAR_EXPRESSION "#t")
add_test(NAME bench/tak COMMAND ./boom test/bench/tak.scm )
set_tests_properties(bench/tak PROPERTIES PASS_REGULAR_EXPRESSION "18")
add_test(NAME bench/divrec COMMAND ./boom --heap-sz=100000 test/bench/divrec.scm )
set_tests_properties(bench/divrec PROPERTIES PASS_REGULAR_EXPRESSION "5000000")
add_test(NAME bench/ack COMMAND ./boom test/bench/ack.scm )
set_tests_properties(bench/ack PROPERTIES PASS_REGULAR_EXPRESSION "4093")
add_test(NAME bench/fib COMMAND ./boom test/bench/fib.scm )
set_tests_properties(bench/fib PROPERTIES PASS_REGULAR_EXPRESSION "9227465")
add_test(NAME bench/diviter COMMAND ./boom --heap-sz=1000000 test/bench/diviter.scm )
set_tests_properties(bench/diviter PROPERTIES PASS_REGULAR_EXPRESSION "50000000")
add_test(NAME bench/sum COMMAND ./boom test/bench/sum.scm )
set_tests_properties(bench/sum PROPERTIES PASS_REGULAR_EXPRESSION "5000050000")
add_test(NAME bench/sumloop COMMAND ./boom test/bench/sumloop.scm )
set_tests_properties(bench/sumloop PROPERTIES PASS_REGULAR_EXPRESSION "1000000000")
add_test(NAME bench/cat COMMAND ./boom  test/bench/cat.scm )
set_tests_properties(bench/cat PROPERTIES PASS_REGULAR_EXPRESSION "END")
add_test(NAME bench/string COMMAND ./boom  test/bench/string.scm )
set_tests_properties(bench/string PROPERTIES PASS_REGULAR_EXPRESSION "1048566")
add_test(NAME bench/cpstak COMMAND ./boom  test/bench/cpstak.scm )
set_tests_properties(bench/cpstak PROPERTIES PASS_REGULAR_EXPRESSION "RESULT: 9")
add_test(NAME bench/array1 COMMAND ./boom  test/bench/array1.scm )
set_tests_properties(bench/array1 PROPERTIES PASS_REGULAR_EXPRESSION "500000")
add_test(NAME bench/pyramid COMMAND ./boom  test/bench/pyramid.scm )
set_tests_properties(bench/pyramid PROPERTIES PASS_REGULAR_EXPRESSION "△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△△")
add_test(NAME bench/nqueens COMMAND ./boom  test/bench/nqueens.scm )
set_tests_properties(bench/nqueens PROPERTIES PASS_REGULAR_EXPRESSION "73712")
add_test(NAME bench/primes COMMAND ./boom  test/bench/primes.scm )
set_tests_properties(bench/primes PROPERTIES PASS_REGULAR_EXPRESSION "2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79")
add_test(NAME bench/takl COMMAND ./boom  test/bench/takl.scm )
set_tests_properties(bench/takl PROPERTIES PASS_REGULAR_EXPRESSION "10 9 8 7 6 5 4 3 2 1")
add_test(NAME bench/deriv COMMAND ./boom  test/bench/deriv.scm )
set_tests_properties(bench/deriv PROPERTIES PASS_REGULAR_EXPRESSION " 3 x x")
add_test(NAME bench/wc COMMAND ./boom  test/bench/wc.scm )
set_tests_properties(bench/wc PROPERTIES PASS_REGULAR_EXPRESSION "1000 26652 137115")
add_test(NAME bench/perm9 COMMAND ./boom  test/bench/perm9.scm )
set_tests_properties(bench/perm9 PROPERTIES PASS_REGULAR_EXPRESSION "16329600")
add_test(NAME bench/mbrot COMMAND ./boom  test/bench/mbrot.scm )
set_tests_properties(bench/mbrot PROPERTIES PASS_REGULAR_EXPRESSION "5")
add_test(NAME bench/pnpoly COMMAND ./boom  test/bench/pnpoly.scm )
set_tests_properties(bench/pnpoly PROPERTIES PASS_REGULAR_EXPRESSION "6")
add_test(NAME bench/destruc COMMAND ./boom  test/bench/destruc.scm )
set_tests_properties(bench/destruc PROPERTIES PASS_REGULAR_EXPRESSION "1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 3")
add_test(NAME bench/triangl COMMAND ./boom  test/bench/triangl.scm )
set_tests_properties(bench/triangl PROPERTIES PASS_REGULAR_EXPRESSION "22 34 31 15 7 1 20 17 25 6 5 13 32")
add_test(NAME bench/dderiv COMMAND ./boom  test/bench/dderiv.scm )
set_tests_properties(bench/dderiv PROPERTIES PASS_REGULAR_EXPRESSION " 3 x x")
add_test(NAME bench/fft COMMAND ./boom  test/bench/fft.scm )
set_tests_properties(bench/fft PROPERTIES PASS_REGULAR_EXPRESSION "21504.0")
add_test(NAME bench/bst COMMAND ./boom  test/bench/BST.scm )
set_tests_properties(bench/bst PROPERTIES PASS_REGULAR_EXPRESSION "3489101213142324254245575887109222")
add_test(NAME bench/nbody COMMAND ./boom  test/bench/nbody.scm )
set_tests_properties(bench/nbody PROPERTIES PASS_REGULAR_EXPRESSION "#t")
add_test(NAME bench/mazefun COMMAND ./boom  test/bench/mazefun.scm )
set_tests_properties(bench/mazefun PROPERTIES PASS_REGULAR_EXPRESSION "_ _ _ _ _ _ _ _ _")
add_test(NAME bench/paraffins COMMAND ./boom  test/bench/paraffins.scm )
set_tests_properties(bench/paraffins PROPERTIES PASS_REGULAR_EXPRESSION "24894")
add_test(NAME bench/browse COMMAND ./boom  test/bench/browse.scm )
set_tests_properties(bench/browse PROPERTIES PASS_REGULAR_EXPRESSION "837 177 1090 617 661 749 628 56 826 408 1035 474 320 452 672 991 155 122 793")
add_test(NAME bench/simplex COMMAND ./boom  test/bench/simplex.scm )
set_tests_properties(bench/simplex PROPERTIES PASS_REGULAR_EXPRESSION "4 1 3 2")
add_test(NAME bench/lattice COMMAND ./boom  test/bench/lattice.scm )
set_tests_properties(bench/lattice PROPERTIES PASS_REGULAR_EXPRESSION "120549")
add_test(NAME bench/conform COMMAND ./boom  test/bench/conform.scm )
set_tests_properties(bench/conform PROPERTIES PASS_REGULAR_EXPRESSION "a b c any none")
add_test(NAME bench/graphs COMMAND ./boom  test/bench/graphs.scm --heap-sz=1000000)
set_tests_properties(bench/graphs PROPERTIES PASS_REGULAR_EXPRESSION "3 2")
add_test(NAME bench/earley COMMAND ./boom  test/bench/earley.scm )
set_tests_properties(bench/earley PROPERTIES PASS_REGULAR_EXPRESSION "1430")
add_test(NAME bench/peval COMMAND ./boom  test/bench/peval.scm )
set_tests_properties(bench/peval PROPERTIES PASS_REGULAR_EXPRESSION "#f")
add_test(NAME bench/boyer COMMAND ./boom  test/bench/boyer.scm )
set_tests_properties(bench/boyer PROPERTIES PASS_REGULAR_EXPRESSION "#t")
add_test(NAME bench/nboyer COMMAND ./boom  test/bench/nboyer.scm --heap-sz=1000000)
set_tests_properties(bench/nboyer PROPERTIES PASS_REGULAR_EXPRESSION "95024591777181397553756781644540651507739")
add_test(NAME bench/sboyer COMMAND ./boom  test/bench/sboyer.scm --heap-sz=1000000)
set_tests_properties(bench/sboyer PROPERTIES PASS_REGULAR_EXPRESSION "9502459177718139755375678")
add_test(NAME bench/nucleic COMMAND ./boom  test/bench/nucleic.scm )
set_tests_properties(bench/nucleic PROPERTIES PASS_REGULAR_EXPRESSION "#t#t")
add_test(NAME bench/compiler COMMAND ./boom  test/bench/compiler.scm)
set_tests_properties(bench/compiler PROPERTIES PASS_REGULAR_EXPRESSION "movl a0,sp@-")

#Gabriel
add_test(NAME bench2/browse COMMAND ./boom  test/bench2/browse.scm)
set_tests_properties(bench2/browse PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/deriv COMMAND ./boom  test/bench2/deriv.scm)
set_tests_properties(bench2/deriv PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/destruc COMMAND ./boom  test/bench2/destruc.scm)
set_tests_properties(bench2/destruc PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/diviter COMMAND ./boom  test/bench2/diviter.scm)
set_tests_properties(bench2/diviter PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/divrec COMMAND ./boom  test/bench2/divrec.scm)
set_tests_properties(bench2/divrec PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/puzzle COMMAND ./boom  test/bench2/puzzle.scm)
set_tests_properties(bench2/puzzle PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/triangl COMMAND ./boom  test/bench2/triangl.scm)
set_tests_properties(bench2/triangl PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/tak COMMAND ./boom  test/bench2/tak.scm)
set_tests_properties(bench2/tak PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/takl COMMAND ./boom  test/bench2/takl.scm)
set_tests_properties(bench2/takl PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/ntakl COMMAND ./boom  test/bench2/ntakl.scm)
set_tests_properties(bench2/ntakl PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/cpstak COMMAND ./boom  test/bench2/cpstak.scm)
set_tests_properties(bench2/cpstak PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/ctak COMMAND ./boom  test/bench2/ctak.scm)
set_tests_properties(bench2/ctak PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

# num benchmarks
add_test(NAME bench2/fib COMMAND ./boom  test/bench2/fib.scm)
set_tests_properties(bench2/fib PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/fibc COMMAND ./boom  test/bench2/fibc.scm)
set_tests_properties(bench2/fibc PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/fibfp COMMAND ./boom  test/bench2/fibfp.scm)
set_tests_properties(bench2/fibfp PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/sum COMMAND ./boom  test/bench2/sum.scm)
set_tests_properties(bench2/sum PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/sumfp COMMAND ./boom  test/bench2/sumfp.scm)
set_tests_properties(bench2/sumfp PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/fft COMMAND ./boom  test/bench2/fft.scm)
set_tests_properties(bench2/fft PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/mbrot COMMAND ./boom  test/bench2/mbrot.scm)
set_tests_properties(bench2/mbrot PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
#add_test(NAME bench2/mbrotZ COMMAND ./boom  test/bench2/mbrotZ.scm)
#set_tests_properties(bench2/mbrotZ PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/nucleic COMMAND ./boom  test/bench2/nucleic.scm)
set_tests_properties(bench2/nucleic PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
# add_test(NAME bench2/pi COMMAND ./boom  test/bench2/pi.scm)
# set_tests_properties(bench2/pi PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/pnpoly COMMAND ./boom  test/bench2/pnpoly.scm)
set_tests_properties(bench2/pnpoly PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/ray COMMAND ./boom  test/bench2/ray.scm)
set_tests_properties(bench2/ray PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/simplex COMMAND ./boom  test/bench2/simplex.scm)
set_tests_properties(bench2/simplex PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

# kwv
add_test(NAME bench2/ack COMMAND ./boom  test/bench2/ack.scm)
set_tests_properties(bench2/ack PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/array1 COMMAND ./boom  test/bench2/array1.scm)
set_tests_properties(bench2/array1 PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/string COMMAND ./boom  test/bench2/string.scm)
set_tests_properties(bench2/string PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/sum1 COMMAND ./boom  test/bench2/sum1.scm)
set_tests_properties(bench2/sum1 PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/cat COMMAND ./boom  test/bench2/cat.scm)
set_tests_properties(bench2/cat PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/tail COMMAND ./boom  test/bench2/tail.scm)
set_tests_properties(bench2/tail PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/wc COMMAND ./boom  test/bench2/wc.scm)
set_tests_properties(bench2/wc PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

# io
add_test(NAME bench2/read1 COMMAND ./boom  test/bench2/read1.scm)
set_tests_properties(bench2/read1 PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

# other
add_test(NAME bench2/compiler COMMAND ./boom  test/bench2/compiler.scm)
set_tests_properties(bench2/compiler PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/conform COMMAND ./boom  test/bench2/conform.scm)
set_tests_properties(bench2/conform PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/dynamic COMMAND ./boom  test/bench2/dynamic.scm)
set_tests_properties(bench2/dynamic PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/earley COMMAND ./boom  test/bench2/earley.scm --heap-sz=1000000)
set_tests_properties(bench2/earley PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/graphs COMMAND ./boom  test/bench2/graphs.scm --heap-sz=100000)
set_tests_properties(bench2/graphs PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/lattice COMMAND ./boom  test/bench2/lattice.scm)
set_tests_properties(bench2/lattice PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/matrix COMMAND ./boom  test/bench2/matrix.scm)
set_tests_properties(bench2/matrix PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/maze COMMAND ./boom  test/bench2/maze.scm)
set_tests_properties(bench2/maze PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/mazefun COMMAND ./boom  test/bench2/mazefun.scm)
set_tests_properties(bench2/mazefun PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/nqueens COMMAND ./boom  test/bench2/nqueens.scm)
set_tests_properties(bench2/nqueens PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/paraffins COMMAND ./boom  test/bench2/paraffins.scm --heap-sz=1000000)
set_tests_properties(bench2/paraffins PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/parsing COMMAND ./boom  test/bench2/parsing.scm)
set_tests_properties(bench2/parsing PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/peval COMMAND ./boom  test/bench2/peval.scm)
set_tests_properties(bench2/peval PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/primes COMMAND ./boom  test/bench2/primes.scm)
set_tests_properties(bench2/primes PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/quicksort COMMAND ./boom  test/bench2/quicksort.scm)
set_tests_properties(bench2/quicksort PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/scheme COMMAND ./boom  test/bench2/scheme.scm)
set_tests_properties(bench2/scheme PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/slatex COMMAND ./boom  test/bench2/slatex.scm)
set_tests_properties(bench2/slatex PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
# add_test(NAME bench2/chudnovsky COMMAND ./boom  test/bench2/chudnovsky.scm)
# set_tests_properties(bench2/chudnovsky PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

# gc
add_test(NAME bench2/nboyer COMMAND ./boom  test/bench2/nboyer.scm --heap-sz=100000)
set_tests_properties(bench2/nboyer PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/sboyer COMMAND ./boom  test/bench2/sboyer.scm --heap-sz=100000)
set_tests_properties(bench2/sboyer PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/gcbench COMMAND ./boom  test/bench2/gcbench.scm --heap-sz=100000)
set_tests_properties(bench2/gcbench PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
add_test(NAME bench2/mperm COMMAND ./boom  test/bench2/mperm.scm --heap-sz=1000000)
set_tests_properties(bench2/mperm PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

# synth
# add_test(NAME bench2/bv2string COMMAND ./boom  test/bench2/bv2string.scm --heap-sz=1000000)
# set_tests_properties(bench2/bv2string PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")
# add_test(NAME bench2/equal COMMAND ./boom  test/bench2/equal.scm --heap-sz=1000000)
# set_tests_properties(bench2/equal PROPERTIES PASS_REGULAR_EXPRESSION "CSVLINE")

#install
install(TARGETS boom_vm boom)
