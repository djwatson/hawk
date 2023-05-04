cmake_minimum_required(VERSION 3.10)

project(bool VERSION 0.1)

enable_language(C)

enable_testing()

#set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-fix;-checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,-readability-magic-numbers")
#set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "iwyu")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_COMPILER "clang")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-no-pie")


# -Wold-style-cast
set(CMAKE_CXX_FLAGS "-O3 -fno-omit-frame-pointer -gdwarf-3 -Wall -Wextra -Wno-unused-parameter  -Wnull-dereference   -Wdouble-promotion -Wshadow -Wformat=2 ")

add_executable(boom
  readbc.cpp bytecode.cpp vm.cpp boom.cpp record.cpp ir.cpp snap.cpp replay.cpp
  )

target_include_directories(boom PUBLIC
  ".")

target_link_libraries(boom PUBLIC
  "stdc++"
  )

add_custom_target(
  cloc
  COMMAND cloc --by-file bc.scm *.h *.cpp
)

add_custom_target(
  format
  COMMAND clang-format -i *.h *.cpp
)
