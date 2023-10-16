
  set(SOURCES readbc.c opcodes.c vm.c bootstrap.c ir.c types.c symbol_table.c gc.c opcodes.h  parallel_copy.c lru.c  third-party/stb_ds.c unionfind.c trace_dump.c jit_stubs.s)
set(SCM_SOURCES ../lib/bc.scm ../lib/passes.scm ../lib/bootstrap.scm ../lib/memory_layout.scm ../lib/bc.chez.scm ../lib/bc.chicken.scm ../lib/util.scm ../lib/str2num.scm)
set(COMPILE_FLAGS -Wall -Wextra -std=gnu11 -I${CMAKE_BINARY_DIR}/src -msse4 -fvisibility=hidden -fomit-frame-pointer -fno-exceptions -Wno-strict-aliasing -Wdouble-promotion -Wshadow -Wno-unused-parameter -Wnull-dereference -Wno-sign-compare -Wno-type-limits -Wno-unused-command-line-argument)
set(LIBRARIES "m")
if (JIT) 
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DJIT")
  set(SOURCES ${SOURCES} snap.c asm_x64.c record.c emit_x64.c)
  if (HAVE_CAPSTONE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCAPSTONE")
    set(LIBRARIES ${LIBRARIES} "capstone")
  endif()
  if (VALGRIND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVALGRIND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -gdwarf-3")
  endif()
  if (HAVE_ELF)
    set(SOURCES ${SOURCES} jitdump.c)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DJITDUMP")
  endif()
endif(JIT)
if (PROFILER)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPROFILER")
  set(SOURCES ${SOURCES} profiler.c)
endif(PROFILER)
add_library(hawk_vm ${SOURCES} )
add_library(hawk_exe exe.c)

target_compile_options(hawk_vm PRIVATE  ${COMPILE_FLAGS} )
target_link_options(hawk_vm PUBLIC -Wl,--gc-sections)
target_compile_options(hawk_exe PRIVATE ${COMPILE_FLAGS} )
set_property(TARGET hawk_vm PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
set_property(TARGET hawk_exe PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_include_directories(hawk_vm PUBLIC ".")

target_link_libraries(hawk_vm PUBLIC ${LIBRARIES}  )
target_link_libraries(hawk_exe PUBLIC hawk_vm  )

set(CLOC_SOURCES ${SOURCES} hawk.c)
list(REMOVE_ITEM CLOC_SOURCES bootstrap.c third-party/stb_ds.c opcodes.c opcodes.h)
add_custom_target(
  cloc
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
  COMMAND cloc --by-file-by-lang ${SCM_SOURCES} ${CLOC_SOURCES} 
)

file(GLOB FORMAT_SOURCES *.c *.h)
list(REMOVE_ITEM FORMAT_SOURCES bootstrap.c third-party/stb_ds.c opcodes-gen.h jit_stubs.s opcodes-gen.h)
add_custom_target(
  format
  COMMAND clang-format -i  ${FORMAT_SOURCES}
  )

# Find a suitable scheme for bootstrapping.
# Chez and chicken have been tested, it's likely most r5rs (+ write-u8) compatible
# schemes will work with minor changes.
find_program(CHEZ chez)
if (NOT CHEZ)
  find_program(CHEZ chezscheme)
endif()
find_program(CSI csi)
find_program(HAWK hawk)
if (CHEZ)
  set(SCHEME_BOOT "${CHEZ}")
  set(SCHEME_BOOT_SCRIPT "--script")
  set(SCHEME_BOOT_EXT ".chez")
elseif(CSI)
  set(SCHEME_BOOT "${CSI}")
  set(SCHEME_BOOT_SCRIPT "-s")
  set(SCHEME_BOOT_EXT ".chicken")
elseif(HAWK)
  set(SCHEME_BOOT "${HAWK}")
  # TODO(djwatson) bug? Shouldn't need joff.
  set(SCHEME_BOOT_SCRIPT "--joff")
  set(SCHEME_BOOT_EXT "")
endif()

# Generate the bootstrap image.
if(SCHEME_BOOT)
  message("Using " ${SCHEME_BOOT} " for bootstrapping")
  add_custom_command(
    OUTPUT  ${CMAKE_SOURCE_DIR}/lib/bootstrap.scm.bc ${CMAKE_SOURCE_DIR}/src/bootstrap.c
    COMMAND
    ${SCHEME_BOOT} ${SCHEME_BOOT_SCRIPT} bc${SCHEME_BOOT_EXT}.scm bootstrap.scm > /dev/null
    COMMAND
    xxd -i bootstrap.scm.bc > ../src/bootstrap.c
    DEPENDS ${SCM_SOURCES} ${CMAKE_SOURCE_DIR}/lib/opcodes.scm
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/lib
    )
  # Generate the opcodes
  add_custom_command(
    OUTPUT ${CMAKE_SOURCE_DIR}/src/opcodes-gen.h ${CMAKE_SOURCE_DIR}/lib/opcodes.scm
    COMMAND
    ${SCHEME_BOOT} ${SCHEME_BOOT_SCRIPT}  ${CMAKE_SOURCE_DIR}/lib/opcode_gen${SCHEME_BOOT_EXT}.scm
    DEPENDS ${CMAKE_SOURCE_DIR}/lib/util.scm ${CMAKE_SOURCE_DIR}/lib/opcode_gen.scm ${CMAKE_SOURCE_DIR}/src/vm.c
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/lib
    )
else()
  message("WARNING: No scheme found for bootstrap, using prebuilt blobs")
endif()

# Actual executable
add_executable(hawk  hawk.c)
target_link_libraries(hawk PUBLIC hawk_vm)
target_compile_options(hawk PRIVATE  ${COMPILE_FLAGS} )
target_link_options(hawk PRIVATE )
set_property(TARGET hawk PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)


