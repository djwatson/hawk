cmake_minimum_required(VERSION 3.20)

project(newhawk C)

set(CMAKE_C_COMPILER clang)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(
  hawk
  hawk.c
  vm.c
  types.c
  record.c
  gc.c
  alloc_table.c
  util/bitset.c
  util/list.c
)

#set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_include_directories(
  hawk PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/util
)
