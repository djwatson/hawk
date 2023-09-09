set(SOURCES readbc.c opcodes.c vm.c bootstrap.c ir.c types.c symbol_table.c gc.c opcodes.h opt_loop.c parallel_copy.c lru.c third-party/stb_ds.c)
set(SCM_SOURCES ../bc.scm ../passes.scm ../bootstrap.scm ../memory_layout.scm ../bc.chez.scm ../bc.chicken.scm ../util.scm ../str2num.scm)
set(COMPILE_FLAGS -fvisibility=hidden -fomit-frame-pointer -fno-rtti -fno-exceptions -Wstrict-aliasing -Wdouble-promotion -Wshadow -Wno-unused-parameter -Wnull-dereference)
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
add_library(boom_vm ${SOURCES} )
add_library(boom_exe exe.c)

target_compile_options(boom_vm PRIVATE  ${COMPILE_FLAGS} )
target_compile_options(boom_exe PRIVATE ${COMPILE_FLAGS} )
set_property(TARGET boom_vm PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
set_property(TARGET boom_exe PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

target_include_directories(boom_vm PUBLIC ".")

target_link_libraries(boom_vm PUBLIC ${LIBRARIES}  )
target_link_libraries(boom_exe PUBLIC boom_vm  )

set(CLOC_SOURCES ${SOURCES} boom.c)
list(REMOVE_ITEM CLOC_SOURCES bootstrap.c third-party/stb_ds.c opcodes.c opcodes.h)
add_custom_target(
  cloc
  COMMAND cloc --by-file-by-lang ${SCM_SOURCES} ${CLOC_SOURCES} 
)

add_custom_target(
  format
  COMMAND clang-format -i *.h *.c
  )

# Generate the bootstrap image.
add_custom_command(
  OUTPUT  bootstrap.scm.bc bootstrap.c
  COMMAND
  mkdir -p third-party
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/bc.chez.scm ${CMAKE_SOURCE_DIR}/bc.scm ${CMAKE_SOURCE_DIR}/memory_layout.scm ${CMAKE_SOURCE_DIR}/passes.scm ${CMAKE_SOURCE_DIR}/bootstrap.scm ${CMAKE_SOURCE_DIR}/str2num.scm .
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/third-party/alexpander.scm third-party/.
  COMMAND
  ${CHEZ} --script bc.chez.scm bootstrap.scm > /dev/null
  COMMAND
  xxd -i bootstrap.scm.bc > bootstrap.c
  DEPENDS ${SCM_SOURCES} opcodes.scm
)

# Generate the opcodes
add_custom_command(
  OUTPUT opcodes.c opcodes.h opcodes-table.h opcodes.scm
  COMMAND
  rsync ${CMAKE_SOURCE_DIR}/opcode_gen.scm ${CMAKE_SOURCE_DIR}/util.scm ${CMAKE_SOURCE_DIR}/src/vm.c .
  COMMAND
  ${CHEZ} --script opcode_gen.scm
  DEPENDS ../util.scm ../opcode_gen.scm vm.c
)

# Actual executable
add_executable(boom  boom.c)
target_link_libraries(boom PUBLIC boom_vm)
target_compile_options(boom PRIVATE  ${COMPILE_FLAGS} )
set_property(TARGET boom PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)


