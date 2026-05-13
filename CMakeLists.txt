cmake_minimum_required(VERSION 3.20)

project(hawk C)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(USE_RANDOM_SCHEDULE "Enable random schedule debugging" OFF)
option(ENABLE_COVERAGE "Enable LLVM source-based coverage instrumentation" OFF)
option(ENABLE_FUZZ_TARGETS "Build fuzz targets" OFF)
option(BOOTSTRAP "Self-host the bootstrap image" OFF)
set(HAWK_DIST_VERSION "" CACHE STRING "Version suffix for the dist tarball")

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CTest)
include(GNUInstallDirs)
include(CheckIPOSupported)

include(CheckIncludeFile)
include(CheckCSourceCompiles)
check_include_file("elf.h" HAVE_ELF_H)

check_ipo_supported(RESULT lto_supported OUTPUT lto_error)
if(lto_supported)
  if(CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
  elseif(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  endif()
endif()

#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

#set(CMAKE_C_CLANG_TIDY "clang-tidy")

set(ASM_SOURCE asm_x64.c)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
  set(ASM_SOURCE asm_aarch64.c)
endif()

if(ENABLE_FUZZ_TARGETS)
  add_subdirectory(fuzz)
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
  ${ASM_SOURCE}
  asm.c
  profiler.c
  util/hashtable.c
  disassemble.c
  parallel_copy.c
  util/array.c
  fold.c
  opt_dce.c
  bc.c
)

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

list(APPEND hawk_sources jitdump.c)
if(NOT HAVE_ELF_H)
  message(STATUS "elf.h not found; using local ELF compat header for jitdump")
endif()

add_library(hawk_core STATIC ${hawk_sources})
add_library(hawk_image_embedded OBJECT hawk_image.c)
target_compile_definitions(hawk_image_embedded PRIVATE BOOTSTRAP=0)

if(BOOTSTRAP)
  add_library(hawk_image_bootstrap OBJECT hawk_image.c)
  target_compile_definitions(hawk_image_bootstrap PRIVATE BOOTSTRAP=1)

  add_executable(hawk_bootstrap $<TARGET_OBJECTS:hawk_image_bootstrap>)
  add_dependencies(hawk_bootstrap hawk_core)
endif()
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

add_executable(hawk $<TARGET_OBJECTS:hawk_image_embedded>)
add_dependencies(hawk hawk_core)
if(BOOTSTRAP)
  add_subdirectory(lib)
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
  target_compile_options(hawk_image_embedded PRIVATE ${coverage_compile_flags})
  if(BOOTSTRAP)
    target_compile_options(hawk_image_bootstrap PRIVATE ${coverage_compile_flags})
  endif()
  if(TARGET gen_fold)
    target_compile_options(gen_fold PRIVATE ${coverage_compile_flags})
    target_link_options(gen_fold PRIVATE ${coverage_link_flags})
  endif()
endif()

function(configure_hawk_target TARGET)
  if(APPLE)
    target_link_libraries(${TARGET} PRIVATE -Wl,-force_load $<TARGET_FILE:hawk_core>)
  else()
    target_link_libraries(${TARGET} PRIVATE -Wl,--whole-archive hawk_core -Wl,--no-whole-archive)
  endif()
  target_link_libraries(${TARGET} PRIVATE ${CAPSTONE_LIBRARY} ${LIBFFI_LIBRARY} ${ZSTD_LIBRARY} m)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(${TARGET} PRIVATE ${CMAKE_DL_LIBS})
    target_link_options(${TARGET} PRIVATE -rdynamic)
  elseif(APPLE)
    target_link_options(${TARGET} PRIVATE -Wl,-export_dynamic)
  endif()
  if(ENABLE_COVERAGE)
    target_compile_options(${TARGET} PRIVATE ${coverage_compile_flags})
    target_link_options(${TARGET} PRIVATE ${coverage_link_flags})
  endif()
endfunction()

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

if(USE_RANDOM_SCHEDULE)
    target_compile_definitions(hawk_core PRIVATE RANDOM_SCHEDULE)
endif()

configure_hawk_target(hawk)
if(BOOTSTRAP)
  configure_hawk_target(hawk_bootstrap)
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

install(TARGETS hawk RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/doc/hawk.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

add_subdirectory(test)

set(dist_bootstrap_build ON)
set(dist_dependencies)
if(BOOTSTRAP)
  set(dist_bootstrap_build OFF)
  list(APPEND dist_dependencies bootstrap_image)
endif()

add_custom_target(
  dist
  COMMAND
    ${CMAKE_COMMAND}
    -DHAWK_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
    -DHAWK_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
    -DHAWK_DIST_VERSION=${HAWK_DIST_VERSION}
    -DHAWK_DIST_BOOTSTRAP_BUILD=${dist_bootstrap_build}
    -DHAWK_DIST_CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DHAWK_DIST_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    -P ${CMAKE_CURRENT_SOURCE_DIR}/Dist.cmake
  DEPENDS ${dist_dependencies}
  COMMENT "Building source release tarball"
  VERBATIM
)
