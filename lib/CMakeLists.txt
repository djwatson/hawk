find_program(GOSH_EXECUTABLE NAMES gosh REQUIRED)

set(OPCODES_SCHEME ${CMAKE_CURRENT_SOURCE_DIR}/opcodes.scm)
add_custom_command(
  OUTPUT ${OPCODES_SCHEME}
  COMMAND
    ${GOSH_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_opcodes.scm
    --header
    ${PROJECT_SOURCE_DIR}/bc.h
    --output
    ${OPCODES_SCHEME}
  COMMAND
    ${CMAKE_COMMAND} -E touch ${OPCODES_SCHEME}
  DEPENDS
    ${PROJECT_SOURCE_DIR}/bc.h
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_opcodes.scm
  COMMENT "Generating Scheme opcode definitions"
  VERBATIM
)

add_custom_target(opcodes_scm ALL DEPENDS ${OPCODES_SCHEME})

set(LIB_IMAGE_BC ${CMAKE_CURRENT_SOURCE_DIR}/gen-image.scm.bc)
set(BOOT_IMAGE_BC ${PROJECT_SOURCE_DIR}/boot/img.scm.bc)

file(
  GLOB LIB_IMAGE_SCHEME_INPUTS CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.scm
  ${CMAKE_CURRENT_SOURCE_DIR}/*.sld
  ${CMAKE_CURRENT_SOURCE_DIR}/srfi2/srfi/*.sld
)

add_custom_command(
  OUTPUT ${BOOT_IMAGE_BC}
  BYPRODUCTS ${LIB_IMAGE_BC}
  COMMAND ${GOSH_EXECUTABLE} -I . -I ./expand/ bc.gosh.scm gen-image.scm
  COMMAND $<TARGET_FILE:hawk_bootstrap>  --image gen-image.scm.bc
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS
    ${LIB_IMAGE_SCHEME_INPUTS}
  COMMENT "Bootstrapping boot/img.scm.bc"
  VERBATIM
)

add_custom_target(bootstrap_image ALL DEPENDS ${BOOT_IMAGE_BC})
add_dependencies(bootstrap_image hawk_bootstrap)
add_dependencies(bootstrap_image opcodes_scm)
add_dependencies(hawk_image_embedded bootstrap_image)
add_dependencies(hawk bootstrap_image)
add_dependencies(hawk_bootstrap opcodes_scm)
