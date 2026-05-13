if(NOT HAWK_SOURCE_DIR)
  message(FATAL_ERROR "HAWK_SOURCE_DIR is required")
endif()
if(NOT HAWK_BINARY_DIR)
  message(FATAL_ERROR "HAWK_BINARY_DIR is required")
endif()

find_package(Git REQUIRED)

if(HAWK_DIST_BOOTSTRAP_BUILD)
  set(bootstrap_build_dir "${HAWK_BINARY_DIR}/dist-bootstrap")
  set(configure_args
    -S "${HAWK_SOURCE_DIR}"
    -B "${bootstrap_build_dir}"
    -DBOOTSTRAP=ON
    -DENABLE_FUZZ_TARGETS=OFF
  )
  if(HAWK_DIST_CMAKE_BUILD_TYPE)
    list(APPEND configure_args -DCMAKE_BUILD_TYPE=${HAWK_DIST_CMAKE_BUILD_TYPE})
  endif()
  if(HAWK_DIST_TOOLCHAIN_FILE)
    list(APPEND configure_args -DCMAKE_TOOLCHAIN_FILE=${HAWK_DIST_TOOLCHAIN_FILE})
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND} ${configure_args}
    WORKING_DIRECTORY "${HAWK_SOURCE_DIR}"
    COMMAND_ERROR_IS_FATAL ANY
  )
  execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${bootstrap_build_dir}" --target bootstrap_image
    WORKING_DIRECTORY "${HAWK_SOURCE_DIR}"
    COMMAND_ERROR_IS_FATAL ANY
  )
endif()

set(boot_image "${HAWK_SOURCE_DIR}/boot/img.scm.bc")
if(NOT EXISTS "${boot_image}")
  message(FATAL_ERROR "Missing generated ${boot_image}")
endif()

if(NOT HAWK_DIST_VERSION)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
    WORKING_DIRECTORY "${HAWK_SOURCE_DIR}"
    OUTPUT_VARIABLE HAWK_DIST_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
  )
endif()

set(dist_name "hawk-${HAWK_DIST_VERSION}")
set(stage_parent "${HAWK_BINARY_DIR}/dist")
set(stage_dir "${stage_parent}/${dist_name}")
set(archive "${HAWK_BINARY_DIR}/${dist_name}.tar.gz")

file(REMOVE_RECURSE "${stage_dir}" "${archive}")
file(MAKE_DIRECTORY "${stage_dir}")

execute_process(
  COMMAND python3 doc/paper/build_paper.py
  WORKING_DIRECTORY "${HAWK_SOURCE_DIR}"
  COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
  COMMAND ${GIT_EXECUTABLE} ls-files
  WORKING_DIRECTORY "${HAWK_SOURCE_DIR}"
  OUTPUT_VARIABLE tracked_files
  OUTPUT_STRIP_TRAILING_WHITESPACE
  COMMAND_ERROR_IS_FATAL ANY
)

string(REPLACE "\n" ";" tracked_files "${tracked_files}")
foreach(path IN LISTS tracked_files)
  get_filename_component(dir "${path}" DIRECTORY)
  file(MAKE_DIRECTORY "${stage_dir}/${dir}")
  file(COPY "${HAWK_SOURCE_DIR}/${path}" DESTINATION "${stage_dir}/${dir}")
endforeach()

file(MAKE_DIRECTORY "${stage_dir}/boot")
file(COPY "${boot_image}" DESTINATION "${stage_dir}/boot")
file(COPY_FILE "${HAWK_SOURCE_DIR}/doc/paper/build/hawk-paper.pdf"
               "${stage_dir}/hawk-paper.pdf")

file(
  ARCHIVE_CREATE
  OUTPUT "${archive}"
  PATHS "${dist_name}"
  FORMAT gnutar
  COMPRESSION GZip
  WORKING_DIRECTORY "${stage_parent}"
)

message(STATUS "Wrote ${archive}")
