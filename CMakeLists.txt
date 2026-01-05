cmake_minimum_required(VERSION 3.20)

project(newhawk C)

option(USE_RANDOM_SCHEDULE "Enable random schedule debugging" OFF)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CTest)

include(CheckIncludeFile)
check_include_file("elf.h" HAVE_ELF_H)

#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

#set(CMAKE_C_CLANG_TIDY "clang-tidy")

set(ASM_SOURCE asm_x64.c)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(ASM_SOURCE asm_aarch64.c)
endif()

set(
  hawk_sources
  hawk.c
  readbc.c
  vm.c
  types.c
  record.c
  gc.c
  ir.c
  alloc_table.c
  emit.c
  ${ASM_SOURCE}
  asm.c
  zone_alloc.c
  profiler.c
  hashtable.c
  disassemble.c
  parallel_copy.c
  profiler.c
  array.c
  util/bitset.c
  util/list.c
  fold.c
  opt_dce.c
  bc.c
)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

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

if(HAVE_ELF_H)
  list(APPEND hawk_sources jitdump.c)
else()
  message(STATUS "elf.h not found; disabling jitdump support")
endif()

add_executable(hawk ${hawk_sources})
add_dependencies(hawk opcodes_scm)
# fold generator
add_executable(host_gen_fold host/gen_fold.c array.c hashtable.c zone_alloc.c)
target_include_directories(
  host_gen_fold PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                        ${CMAKE_CURRENT_SOURCE_DIR}/util)
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/fold_gen.h
  COMMAND host_gen_fold ${CMAKE_CURRENT_SOURCE_DIR}/fold.c >
          ${CMAKE_CURRENT_BINARY_DIR}/fold_gen.h
  DEPENDS host_gen_fold fold.c
  COMMENT "Generating fold lookup table"
  VERBATIM)
add_custom_target(fold_gen DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/fold_gen.h)
add_dependencies(hawk fold_gen)
#set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

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

target_link_libraries(hawk PRIVATE ${CAPSTONE_LIBRARY})

if(HAVE_ELF_H)
  target_compile_definitions(hawk PRIVATE HAVE_ELF_H=1)
endif()

#set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

if(USE_RANDOM_SCHEDULE)
    target_compile_definitions(hawk PRIVATE RANDOM_SCHEDULE)
endif()

target_include_directories(
  hawk PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/util
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CAPSTONE_INCLUDE_DIR}
)

if(BUILD_TESTING)
  add_test(
    NAME hawk_sum
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sum.scm.bc
  )
  set_tests_properties(
    hawk_sum PROPERTIES PASS_REGULAR_EXPRESSION "500000000500000000"
  )

  add_test(
    NAME hawk_sumfp
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sumfp.scm.bc
  )
  set_tests_properties(
    hawk_sumfp PROPERTIES PASS_REGULAR_EXPRESSION "2.5e\\+14"
  )

  add_test(
    NAME hawk_summix
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/summix.scm.bc
  )
  set_tests_properties(
    hawk_summix PROPERTIES PASS_REGULAR_EXPRESSION "50000000500000005e\\+155000000050000000"
  )

  add_test(
    NAME hawk_sum1
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/sum1.scm.bc
  )
  set_tests_properties(hawk_sum1 PROPERTIES PASS_REGULAR_EXPRESSION "500001500001")

  add_test(
    NAME hawk_tak
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/tak.scm.bc
  )
  set_tests_properties(hawk_tak PROPERTIES PASS_REGULAR_EXPRESSION "12")

  add_test(
    NAME hawk_ack
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/ack.scm.bc
  )
  set_tests_properties(
    hawk_ack PROPERTIES PASS_REGULAR_EXPRESSION "32765"
  )

  add_test(
    NAME hawk_fib
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/fib.scm.bc
  )
  set_tests_properties(
    hawk_fib PROPERTIES PASS_REGULAR_EXPRESSION "102334155"
  )

  add_test(
    NAME hawk_fibfp
    COMMAND $<TARGET_FILE:hawk> ${CMAKE_CURRENT_SOURCE_DIR}/test/fibfp.scm.bc
  )
  set_tests_properties(
    hawk_fibfp PROPERTIES PASS_REGULAR_EXPRESSION "9.22746e\\+06"
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
