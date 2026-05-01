cmake_minimum_required(VERSION 3.20)

set(CMAKE_C_COMPILER clang CACHE STRING "C compiler")

project(newhawk C)

option(USE_RANDOM_SCHEDULE "Enable random schedule debugging" OFF)
option(ENABLE_COVERAGE "Enable LLVM source-based coverage instrumentation" OFF)
option(ENABLE_REGALLOC_FUZZ "Build regalloc libFuzzer target when supported" ON)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CTest)

include(CheckIncludeFile)
include(CheckCSourceCompiles)
check_include_file("elf.h" HAVE_ELF_H)

#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

#set(CMAKE_C_CLANG_TIDY "clang-tidy")

set(ASM_SOURCE asm_x64.c)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(ASM_SOURCE asm_aarch64.c)
endif()

if(ENABLE_REGALLOC_FUZZ AND CMAKE_C_COMPILER_ID MATCHES "Clang")
  if(DEFINED HAVE_LIBFUZZER_RUNTIME)
    unset(HAVE_LIBFUZZER_RUNTIME CACHE)
  endif()
  set(_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
  set(_saved_try_compile_target_type "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
  set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -fsanitize=fuzzer,address")
  set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
  check_c_source_compiles(
    "
      int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {
        (void)Data;
        (void)Size;
        return 0;
      }
    "
    HAVE_LIBFUZZER_RUNTIME)
  set(CMAKE_REQUIRED_FLAGS "${_saved_required_flags}")
  set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_saved_try_compile_target_type}")

  if(HAVE_LIBFUZZER_RUNTIME)
    add_executable(
      regalloc_fuzz
      fuzz/regalloc_fuzz.c
      ftoa.c
      regalloc.c
      lru.c
      ir.c
      types.c
      ${ASM_SOURCE}
      asm.c
      util/array.c
    )
    target_compile_options(regalloc_fuzz PRIVATE -fsanitize=fuzzer,address)
    target_link_options(regalloc_fuzz PRIVATE -fsanitize=fuzzer,address)
    target_include_directories(
      regalloc_fuzz PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/util
      ${CMAKE_CURRENT_BINARY_DIR}
    )
  else()
    message(STATUS "Skipping regalloc_fuzz: libFuzzer runtime not available")
  endif()
endif()

set(
  hawk_sources
  hawk.c
  runtime.c
  equal.c
  bigint.c
  ftoa.c
  vm.c
  foreign.c
  types.c
  record.c
  gc.c
  ir.c
  emit.c
  regalloc.c
  lru.c
  ${ASM_SOURCE}
  asm.c
  comments.c
  profiler.c
  util/hashtable.c
  disassemble.c
  parallel_copy.c
  profiler.c
  util/array.c
  fold.c
  opt_dce.c
  bc.c
)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(libffi_search_dirs)
if(DEFINED ENV{HOMEBREW_PREFIX})
  list(APPEND libffi_search_dirs $ENV{HOMEBREW_PREFIX}/include $ENV{HOMEBREW_PREFIX}/lib)
  list(APPEND libffi_search_dirs $ENV{HOMEBREW_PREFIX}/opt/libffi/include $ENV{HOMEBREW_PREFIX}/opt/libffi/lib)
endif()
list(APPEND libffi_search_dirs /opt/homebrew/include /opt/homebrew/lib /opt/homebrew/opt/libffi/include /opt/homebrew/opt/libffi/lib /usr/local/include /usr/local/lib /usr/local/opt/libffi/include /usr/local/opt/libffi/lib)

find_path(LIBFFI_INCLUDE_DIR NAMES ffi.h PATHS ${libffi_search_dirs})
find_library(LIBFFI_LIBRARY NAMES ffi libffi PATHS ${libffi_search_dirs})

if(NOT LIBFFI_INCLUDE_DIR)
  message(FATAL_ERROR "ffi.h not found. Install libffi or set LIBFFI_INCLUDE_DIR.")
endif()

if(NOT LIBFFI_LIBRARY)
  message(FATAL_ERROR "libffi not found. Install libffi or set LIBFFI_LIBRARY.")
endif()

set(zstd_search_dirs)
if(DEFINED ENV{HOMEBREW_PREFIX})
  list(APPEND zstd_search_dirs $ENV{HOMEBREW_PREFIX}/include $ENV{HOMEBREW_PREFIX}/lib)
  list(APPEND zstd_search_dirs $ENV{HOMEBREW_PREFIX}/opt/zstd/include $ENV{HOMEBREW_PREFIX}/opt/zstd/lib)
endif()
list(APPEND zstd_search_dirs /opt/homebrew/include /opt/homebrew/lib /usr/local/include /usr/local/lib /usr/include /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu)

find_path(ZSTD_INCLUDE_DIR NAMES zstd.h PATHS ${zstd_search_dirs})
find_library(ZSTD_LIBRARY NAMES zstd PATHS ${zstd_search_dirs})

if(NOT ZSTD_INCLUDE_DIR)
  message(FATAL_ERROR "zstd.h not found. Install zstd or set ZSTD_INCLUDE_DIR.")
endif()

if(NOT ZSTD_LIBRARY)
  message(FATAL_ERROR "libzstd not found. Install zstd or set ZSTD_LIBRARY.")
endif()

set(OPCODES_SCHEME ${CMAKE_CURRENT_SOURCE_DIR}/lib/opcodes.scm)
add_custom_command(
  OUTPUT ${OPCODES_SCHEME}
  COMMAND
    ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_opcodes.py
    --header
    ${CMAKE_CURRENT_SOURCE_DIR}/bc.h
    --output
    ${OPCODES_SCHEME}
  COMMAND
    ${CMAKE_COMMAND} -E touch ${OPCODES_SCHEME}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/bc.h
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_opcodes.py
  COMMENT "Generating Scheme opcode definitions"
  VERBATIM
)

add_custom_target(opcodes_scm ALL DEPENDS ${OPCODES_SCHEME})

list(APPEND hawk_sources jitdump.c)
if(NOT HAVE_ELF_H)
  message(STATUS "elf.h not found; using local ELF compat header for jitdump")
endif()

add_library(hawk_core STATIC ${hawk_sources})
add_library(hawk_image_bootstrap OBJECT hawk_image.c)
target_compile_definitions(hawk_image_bootstrap PRIVATE BOOTSTRAP=1)
add_library(hawk_image_embedded OBJECT hawk_image.c)
target_compile_definitions(hawk_image_embedded PRIVATE BOOTSTRAP=0)

add_executable(hawk_bootstrap $<TARGET_OBJECTS:hawk_image_bootstrap>)
add_dependencies(hawk_bootstrap opcodes_scm)

set(LIB_IMAGE_BC ${CMAKE_CURRENT_SOURCE_DIR}/lib/img.scm.bc)
if(NOT EXISTS "${LIB_IMAGE_BC}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E touch "${LIB_IMAGE_BC}")
endif()
set(LIB_IMAGE_STAMP ${CMAKE_CURRENT_BINARY_DIR}/lib_image.stamp)
# fold generator
set(gen_fold_target gen_fold)
set(
  gen_fold_sources
  host/gen_fold.c
  util/array.c
  util/hashtable.c
)
set(gen_fold_source_paths)
foreach(src ${gen_fold_sources})
  list(APPEND gen_fold_source_paths
       ${CMAKE_CURRENT_SOURCE_DIR}/${src})
endforeach()
set(
  gen_fold_includes
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/util
)
set(gen_fold_exe $<TARGET_FILE:gen_fold>)
set(gen_fold_include_flags)
foreach(dir ${gen_fold_includes})
  list(APPEND gen_fold_include_flags -I${dir})
endforeach()
if(CMAKE_CROSSCOMPILING)
  set(gen_fold_target gen_fold_host)
  set(gen_fold_exe ${CMAKE_CURRENT_BINARY_DIR}/gen_fold_tool)
  find_program(HOST_CC NAMES clang cc)
  if(NOT HOST_CC)
    message(FATAL_ERROR "No host C compiler found to build gen_fold")
  endif()
  add_custom_command(
    OUTPUT ${gen_fold_exe}
    COMMAND
      ${HOST_CC}
      -std=c23
      -O2
      -g
      ${gen_fold_include_flags}
      ${gen_fold_source_paths}
      -o ${gen_fold_exe}
    DEPENDS ${gen_fold_source_paths}
    BYPRODUCTS ${gen_fold_exe}
    COMMENT "Building host gen_fold tool for codegen"
    VERBATIM
  )
  add_custom_target(${gen_fold_target} DEPENDS ${gen_fold_exe})
else()
  add_executable(gen_fold ${gen_fold_sources})
  target_include_directories(gen_fold PRIVATE ${gen_fold_includes})
endif()
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/fold_gen.h
  COMMAND ${gen_fold_exe} ${CMAKE_CURRENT_SOURCE_DIR}/fold.c >
          ${CMAKE_CURRENT_BINARY_DIR}/fold_gen.h
  DEPENDS ${gen_fold_target} fold.c
  COMMENT "Generating fold lookup table"
  VERBATIM)
add_custom_target(fold_gen DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/fold_gen.h)
add_dependencies(hawk_core fold_gen)

find_program(GOSH_EXECUTABLE NAMES gosh REQUIRED)
file(
  GLOB LIB_IMAGE_SCHEME_INPUTS CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/*.scm
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/*.sld
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/srfi2/srfi/*.sld
)
add_custom_command(
  OUTPUT ${LIB_IMAGE_STAMP}
  COMMAND ${GOSH_EXECUTABLE} -I . -I ./expand/ bc.gosh.scm gen-image.scm
  COMMAND $<TARGET_FILE:hawk_bootstrap> --joff --image gen-image.scm.bc
  COMMAND ${CMAKE_COMMAND} -E touch ${LIB_IMAGE_STAMP}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib
  DEPENDS
    ${LIB_IMAGE_SCHEME_INPUTS}
  COMMENT "Bootstrapping lib/img.scm.bc"
  VERBATIM
)
add_custom_target(bootstrap_image ALL DEPENDS ${LIB_IMAGE_STAMP})
add_dependencies(bootstrap_image hawk_bootstrap)
add_dependencies(hawk_image_embedded bootstrap_image)

add_executable(hawk $<TARGET_OBJECTS:hawk_image_embedded>)
add_dependencies(hawk opcodes_scm)

if(APPLE)
  target_link_libraries(hawk_bootstrap PRIVATE -Wl,-force_load $<TARGET_FILE:hawk_core>)
  target_link_libraries(hawk PRIVATE -Wl,-force_load $<TARGET_FILE:hawk_core>)
else()
  target_link_libraries(hawk_bootstrap PRIVATE -Wl,--whole-archive hawk_core -Wl,--no-whole-archive)
  target_link_libraries(hawk PRIVATE -Wl,--whole-archive hawk_core -Wl,--no-whole-archive)
endif()

if(ENABLE_COVERAGE)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(coverage_compile_flags -O0 -g -fprofile-instr-generate -fcoverage-mapping)
    set(coverage_link_flags -fprofile-instr-generate -fcoverage-mapping)
  elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(coverage_compile_flags -O0 -g --coverage)
    set(coverage_link_flags --coverage)
  else()
    message(FATAL_ERROR "Coverage is only supported with Clang or GCC compilers.")
  endif()

  target_compile_options(hawk_core PRIVATE ${coverage_compile_flags})
  target_compile_options(hawk_image_bootstrap PRIVATE ${coverage_compile_flags})
  target_compile_options(hawk_image_embedded PRIVATE ${coverage_compile_flags})
  target_compile_options(hawk_bootstrap PRIVATE ${coverage_compile_flags})
  target_link_options(hawk_bootstrap PRIVATE ${coverage_link_flags})
  target_compile_options(hawk PRIVATE ${coverage_compile_flags})
  target_link_options(hawk PRIVATE ${coverage_link_flags})

  if(TARGET gen_fold)
    target_compile_options(gen_fold PRIVATE ${coverage_compile_flags})
    target_link_options(gen_fold PRIVATE ${coverage_link_flags})
  endif()
endif()

set(capstone_search_dirs)
if(DEFINED ENV{HOMEBREW_PREFIX})
  list(APPEND capstone_search_dirs $ENV{HOMEBREW_PREFIX}/include)
endif()
list(APPEND capstone_search_dirs /opt/homebrew/include /usr/local/include)

find_path(
  CAPSTONE_INCLUDE_DIR
  NAMES capstone/capstone.h
  PATHS ${capstone_search_dirs}
)

if(NOT CAPSTONE_INCLUDE_DIR)
  message(FATAL_ERROR "capstone/capstone.h not found. Install capstone or set CAPSTONE_INCLUDE_DIR.")
endif()

set(capstone_library_dirs)
if(DEFINED ENV{HOMEBREW_PREFIX})
  list(APPEND capstone_library_dirs $ENV{HOMEBREW_PREFIX}/lib)
endif()
list(APPEND capstone_library_dirs /opt/homebrew/lib /usr/local/lib)

find_library(
  CAPSTONE_LIBRARY
  NAMES capstone
  PATHS ${capstone_library_dirs}
)

if(NOT CAPSTONE_LIBRARY)
  message(FATAL_ERROR "libcapstone not found. Install capstone or set CAPSTONE_LIBRARY.")
endif()

target_link_libraries(hawk_bootstrap PRIVATE ${CAPSTONE_LIBRARY} ${LIBFFI_LIBRARY} ${ZSTD_LIBRARY} m)
target_link_libraries(hawk PRIVATE ${CAPSTONE_LIBRARY} ${LIBFFI_LIBRARY} ${ZSTD_LIBRARY} m)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(hawk_bootstrap PRIVATE ${CMAKE_DL_LIBS})
  target_link_options(hawk_bootstrap PRIVATE -rdynamic)
  target_link_libraries(hawk PRIVATE ${CMAKE_DL_LIBS})
  target_link_options(hawk PRIVATE -rdynamic)
elseif(APPLE)
  target_link_options(hawk_bootstrap PRIVATE -Wl,-export_dynamic)
  target_link_options(hawk PRIVATE -Wl,-export_dynamic)
endif()

set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
set_property(TARGET hawk_core PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
set_property(TARGET hawk_bootstrap PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
# target_compile_options(hawk PRIVATE -march=native)
# target_compile_options(hawk PRIVATE -O3)

if(USE_RANDOM_SCHEDULE)
    target_compile_definitions(hawk_core PRIVATE RANDOM_SCHEDULE)
endif()

target_include_directories(
  hawk_core PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/util
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CAPSTONE_INCLUDE_DIR}
  ${LIBFFI_INCLUDE_DIR}
  ${ZSTD_INCLUDE_DIR}
)

if(BUILD_TESTING)
  add_test(
    NAME hawk_sum
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sum.scm
  )
  set_tests_properties(
    hawk_sum PROPERTIES PASS_REGULAR_EXPRESSION "500000000500000000"
  )

  add_test(
    NAME hawk_sumfp
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sumfp.scm
  )
  set_tests_properties(
    hawk_sumfp PROPERTIES PASS_REGULAR_EXPRESSION "2.5000025e\\+14"
  )

  add_test(
    NAME hawk_summix
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/summix.scm
  )
  set_tests_properties(
    hawk_summix PROPERTIES PASS_REGULAR_EXPRESSION "50000000500000005.00000005e\\+155000000050000000"
  )

  add_test(
    NAME hawk_sum1
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sum1.scm
  )
  set_tests_properties(hawk_sum1 PROPERTIES PASS_REGULAR_EXPRESSION "500001500001")

  add_test(
    NAME hawk_sumloop
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sumloop.scm
  )
  set_tests_properties(hawk_sumloop PROPERTIES PASS_REGULAR_EXPRESSION "1000000000")

  add_test(
    NAME hawk_tak
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/tak.scm
  )
  set_tests_properties(hawk_tak PROPERTIES PASS_REGULAR_EXPRESSION "12")

  add_test(
    NAME hawk_takl
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/takl.scm
  )
  set_tests_properties(
    hawk_takl PROPERTIES PASS_REGULAR_EXPRESSION
                         "\\(6 5 4 3 2 1\\).*\n\\(7 6 5 4 3 2 1\\).*\n\\(10 9 8 7 6 5 4 3 2 1\\).*\n\\(13 12 11 10 9 8 7 6 5 4 3 2 1\\)"
  )

  add_test(
    NAME hawk_cpstak
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/cpstak.scm
  )
  set_tests_properties(
    hawk_cpstak PROPERTIES PASS_REGULAR_EXPRESSION "RESULT: 9"
  )

  add_test(
    NAME hawk_ack
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/ack.scm
  )
  set_tests_properties(
    hawk_ack PROPERTIES PASS_REGULAR_EXPRESSION "32765"
  )

  add_test(
    NAME hawk_fib
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/fib.scm
  )
  set_tests_properties(
    hawk_fib PROPERTIES PASS_REGULAR_EXPRESSION "102334155"
  )

  add_test(
    NAME hawk_fibfp
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/fibfp.scm
  )
  set_tests_properties(
    hawk_fibfp PROPERTIES PASS_REGULAR_EXPRESSION "9227465.0"
  )

  add_test(
    NAME hawk_diviter
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/diviter.scm
  )
  set_tests_properties(
    hawk_diviter PROPERTIES PASS_REGULAR_EXPRESSION "500"
  )

  add_test(
    NAME hawk_divrec
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/divrec.scm
  )
  set_tests_properties(
    hawk_divrec PROPERTIES PASS_REGULAR_EXPRESSION "500"
  )

  add_test(
    NAME hawk_nqueens
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/nqueens.scm
  )
  set_tests_properties(
    hawk_nqueens PROPERTIES PASS_REGULAR_EXPRESSION "73712"
  )

  add_test(
    NAME hawk_primes
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/primes.scm
  )
  set_tests_properties(
    hawk_primes PROPERTIES PASS_REGULAR_EXPRESSION "\\(2 3 5 7 11 13.*983 991 997\\)"
  )

  add_test(
    NAME hawk_array2
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/array2.scm
  )
  set_tests_properties(
    hawk_array2 PROPERTIES PASS_REGULAR_EXPRESSION "1000000"
  )

  add_test(
    NAME hawk_deriv
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/deriv.scm
  )
  set_tests_properties(
    hawk_deriv PROPERTIES PASS_REGULAR_EXPRESSION "\\(\\+ \\(\\* \\(\\* 3 x x\\)"
  )

  add_test(
    NAME hawk_quicksort
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/quicksort.scm
  )

  add_test(
    NAME hawk_pnpoly
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/pnpoly.scm
  )
  set_tests_properties(
    hawk_pnpoly PROPERTIES PASS_REGULAR_EXPRESSION "6"
  )

  add_test(
    NAME hawk_triangl
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/triangl.scm
  )
  set_tests_properties(
    hawk_triangl PROPERTIES PASS_REGULAR_EXPRESSION "\\(22 34 31 15 7 1 20 17 25 6 5 13 32\\)"
  )

  add_test(
    NAME hawk_simplex
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/simplex.scm
  )
  set_tests_properties(
    hawk_simplex PROPERTIES PASS_REGULAR_EXPRESSION "\\(#\\(4 1 3 2\\) #\\(0 5 7 6\\)\\)"
  )

  add_test(
    NAME hawk_perm9
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/perm9.scm
  )
  set_tests_properties(
    hawk_perm9 PROPERTIES PASS_REGULAR_EXPRESSION "16329600"
  )

  add_test(
    NAME hawk_fft
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/fft.scm
  )
  set_tests_properties(
    hawk_fft PROPERTIES PASS_REGULAR_EXPRESSION "0\\.0"
  )

  add_test(
    NAME hawk_mbrot
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/mbrot.scm
  )
  set_tests_properties(
    hawk_mbrot PROPERTIES PASS_REGULAR_EXPRESSION "5"
  )
endif()

file(
  GLOB
  extra_clean_files
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/*.dump"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.so"
  "${CMAKE_CURRENT_SOURCE_DIR}/perf.*"
  "${CMAKE_CURRENT_SOURCE_DIR}/*~"
)
if(extra_clean_files)
  set_property(
    DIRECTORY
    APPEND
    PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
    ${extra_clean_files}
  )
endif()
