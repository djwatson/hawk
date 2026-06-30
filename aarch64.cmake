# Tell CMake we’re cross-compiling for Linux on AArch64.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Use Clang frontends.
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Target triple and sysroot (adjust if yours differs).
set(TARGET_TRIPLE aarch64-linux-gnu)
set(SYSROOT /usr/aarch64-linux-gnu)

# Discover the GCC cross toolchain directory (needed for crt objects and libgcc).
set(GCC_CROSS_BASE /usr/lib/gcc-cross/${TARGET_TRIPLE})
file(GLOB GCC_CROSS_DIRS "${GCC_CROSS_BASE}/*")
if(NOT GCC_CROSS_DIRS)
  message(FATAL_ERROR "Unable to locate GCC cross toolchain under ${GCC_CROSS_BASE}")
endif()
list(SORT GCC_CROSS_DIRS)
list(REVERSE GCC_CROSS_DIRS)
list(GET GCC_CROSS_DIRS 0 GCC_TOOLCHAIN_DIR)

# Tell Clang which target to build for.
set(CMAKE_C_COMPILER_TARGET   ${TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_ASM_COMPILER_TARGET ${TARGET_TRIPLE})

# Clang needs help finding the GCC-provided startup files and libgcc.
set(COMMON_TARGET_FLAGS "--target=${TARGET_TRIPLE} --sysroot=${SYSROOT} -B${GCC_TOOLCHAIN_DIR}")

# Propagate flags to all build types.
set(CMAKE_C_FLAGS_INIT   "${COMMON_TARGET_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "${COMMON_TARGET_FLAGS}")
set(CMAKE_ASM_FLAGS_INIT "${COMMON_TARGET_FLAGS}")

# Linker flags (use lld, surface libgcc, and undo the sysroot override for absolute GNU ld scripts).
set(COMMON_LINK_FLAGS "-fuse-ld=lld -L${GCC_TOOLCHAIN_DIR} -Wl,--sysroot=/")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${COMMON_LINK_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${COMMON_LINK_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${COMMON_LINK_FLAGS}")

# Prefer LLVM binutils (optional but nice).
# If you want to ensure archiving/ranlib/strip are LLVM’s tools:
find_program(LLVM_AR NAMES llvm-ar)
find_program(LLVM_RANLIB NAMES llvm-ranlib)
find_program(LLVM_STRIP NAMES llvm-strip)
if(LLVM_AR)
  set(CMAKE_AR "${LLVM_AR}" CACHE FILEPATH "" FORCE)
endif()
if(LLVM_RANLIB)
  set(CMAKE_RANLIB "${LLVM_RANLIB}" CACHE FILEPATH "" FORCE)
endif()
if(LLVM_STRIP)
  set(CMAKE_STRIP "${LLVM_STRIP}" CACHE FILEPATH "" FORCE)
endif()

# Make CMake search headers/libs inside the sysroot first.
set(CMAKE_FIND_ROOT_PATH "${SYSROOT}")

# Typical cross-compile search behavior:
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)   # don’t search sysroot for host tools
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)    # libraries from target sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)    # headers from target sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Avoid try-run during configure (we can’t run target binaries on the host).
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
