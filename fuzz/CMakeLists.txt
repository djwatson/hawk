if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(STATUS "Skipping regalloc_fuzz: libFuzzer requires Clang")
  return()
endif()

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

if(NOT HAVE_LIBFUZZER_RUNTIME)
  message(STATUS "Skipping regalloc_fuzz: libFuzzer runtime not available")
  return()
endif()

add_executable(
  regalloc_fuzz
  regalloc_fuzz.c
  ../ftoa.c
  ../regalloc.c
  ../lru.c
  ../ir.c
  ../types.c
  ../${ASM_SOURCE}
  ../asm.c
  ../util/array.c
)
target_compile_options(regalloc_fuzz PRIVATE -fsanitize=fuzzer,address)
target_link_options(regalloc_fuzz PRIVATE -fsanitize=fuzzer,address)
target_include_directories(
  regalloc_fuzz PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../util
  ${CMAKE_BINARY_DIR}
)
