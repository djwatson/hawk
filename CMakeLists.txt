cmake_minimum_required(VERSION 3.20)

project(newhawk C)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

#set(CMAKE_C_CLANG_TIDY "clang-tidy")

add_executable(
  hawk
  hawk.c
  vm.c
  types.c
  record.c
  gc.c
  vec.c
  ir.c
  alloc_table.c
  emit.c
  asm_x64.c
  x64.c
  util/bitset.c
  util/list.c
)

target_link_libraries(hawk PRIVATE capstone)

#set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_include_directories(
  hawk PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/util
)
