cmake_minimum_required(VERSION 3.20)

project(newhawk C)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

#set(CMAKE_C_CLANG_TIDY "clang-tidy")

set(ASM_SOURCE asm_x64.c)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(ASM_SOURCE asm_aarch64.c)
endif()

add_executable(
  hawk
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
  jitdump.c
  hashtable.c
  disassemble.c
  array.c
  util/bitset.c
  util/list.c
)

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

#set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_include_directories(
  hawk PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/util
  ${CAPSTONE_INCLUDE_DIR}
)
