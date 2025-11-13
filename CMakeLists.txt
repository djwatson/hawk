cmake_minimum_required(VERSION 3.20)

project(newhawk C)

option(USE_RANDOM_SCHEDULE "Enable random schedule debugging" OFF)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

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
  opt_dce.c
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
  ${CAPSTONE_INCLUDE_DIR}
)
