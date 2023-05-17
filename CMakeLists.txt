cmake_minimum_required(VERSION 3.14)

project(bool VERSION 0.1)

enable_language(C)

enable_testing()

option(JIT "Enable JIT" OFF)

find_program(CHEZ chez)
if (NOT CHEZ)
  find_program(CHEZ chezscheme)
  if (NOT CHEZ)
    message(FATAL_ERROR "Can't find chez scheme for bootstrapping")
  endif()
endif()
message("Using " ${CHEZ} " for bootstrapping")

#set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-fix;-checks=clang-diagnostic-*,clang-analyzer-*,bugprone*,modernize*,performance*,readability-*,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,-readability-magic-numbers")
#set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "iwyu")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_COMPILER "clang")

include(CheckPIESupported)
check_pie_supported()

# -Wold-style-cast
set(CMAKE_CXX_FLAGS "-O3 -DNDEBUG -fomit-frame-pointer -gdwarf-3 -Wall -Wextra -Wno-unused-parameter  -Wnull-dereference   -Wdouble-promotion -Wshadow -Wformat=2 -flto -fvisibility=hidden")

set(SOURCES readbc.cpp bytecode.cpp vm.cpp boom.cpp  ir.cpp types.cpp vm_startup.h)
set(LIBRARIES "stdc++" "m")
if (JIT) 
  set(SOURCES ${SOURCES} snap.cpp replay.cpp asm_x64.cpp jitdump.cpp record.cpp)
  set(LIBRARIES ${LIBRARIES} "asmjit" "capstone")
endif(JIT)
add_executable(boom ${SOURCES} )


set_property(TARGET boom PROPERTY POSITION_INDEPENDENT_CODE FALSE)
target_include_directories(boom PUBLIC
  ".")

target_link_libraries(boom PUBLIC ${LIBRARIES}  )

add_custom_target(
  cloc
  COMMAND cloc --by-file-by-lang *.scm *.h *.cpp
)

add_custom_target(
  format
  COMMAND clang-format -i *.h *.cpp
)

add_custom_command(
  OUTPUT  out.bc
  COMMAND
  ${CHEZ} --script bc.chez.scm < bc.boom.scm
  xxd -i out.bc > vm_startup.h
  DEPENDS bc.scm passes.scm
)

add_custom_command(
  OUTPUT  vm_startup.h
  COMMAND
  xxd -i out.bc > vm_startup.h
  DEPENDS out.bc
)
