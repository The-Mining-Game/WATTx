# Copyright (c) 2024-2026 The WATTx Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# CMake configuration for FCMP library with Rust FFI

# Find required tools
find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
    message(WARNING "cargo not found - FCMP Rust library will not be built")
    set(WATTX_FCMP_ENABLED OFF CACHE BOOL "FCMP library enabled" FORCE)
    return()
endif()

# FORCE here is REQUIRED, not optional. Without it, a build directory that was
# first configured on a machine with no cargo keeps the OFF value written above
# forever: a plain set(... CACHE ...) never overwrites an existing cache entry,
# so installing Rust and re-running cmake silently leaves FCMP disabled and the
# link then fails with undefined references to fcmp_init/fcmp_error_string.
set(WATTX_FCMP_ENABLED ON CACHE BOOL "FCMP library enabled" FORCE)

# Rust build configuration
set(RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust)
set(RUST_TARGET_DIR ${RUST_DIR}/target)
set(RUST_RELEASE_DIR ${RUST_TARGET_DIR}/release)

# Determine static library name and cargo target based on platform
if(WIN32 AND CMAKE_CROSSCOMPILING)
    set(RUST_TARGET "x86_64-pc-windows-gnu")
    set(RUST_LIB_NAME libwattx_fcmp.a)
    set(RUST_RELEASE_DIR ${RUST_TARGET_DIR}/${RUST_TARGET}/release)
    set(CARGO_TARGET_FLAG --target ${RUST_TARGET})
elseif(WIN32)
    set(RUST_LIB_NAME wattx_fcmp.lib)
    set(CARGO_TARGET_FLAG "")
elseif(APPLE AND CMAKE_CROSSCOMPILING)
    set(RUST_TARGET "x86_64-apple-darwin")
    set(RUST_LIB_NAME libwattx_fcmp.a)
    set(RUST_RELEASE_DIR ${RUST_TARGET_DIR}/${RUST_TARGET}/release)
    set(CARGO_TARGET_FLAG --target ${RUST_TARGET})
elseif(ANDROID)
    # Phones are arm64; the 32-bit ABI is not built because a validating node
    # needs the 64-bit address space for the RandomX cache.
    set(RUST_TARGET "aarch64-linux-android")
    set(RUST_LIB_NAME libwattx_fcmp.a)
    set(RUST_RELEASE_DIR ${RUST_TARGET_DIR}/${RUST_TARGET}/release)
    set(CARGO_TARGET_FLAG --target ${RUST_TARGET})
elseif(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
       AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    # Cross-building for 64-bit ARM Linux (e.g. an Oracle Ampere A1 seed node).
    # Without an explicit --target, cargo builds for the HOST arch and the x86
    # objects only surface much later as undefined references at link time.
    # Needs: rustup target add aarch64-unknown-linux-gnu, and
    # CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    set(RUST_TARGET "aarch64-unknown-linux-gnu")
    set(RUST_LIB_NAME libwattx_fcmp.a)
    set(RUST_RELEASE_DIR ${RUST_TARGET_DIR}/${RUST_TARGET}/release)
    set(CARGO_TARGET_FLAG --target ${RUST_TARGET})
else()
    set(RUST_LIB_NAME libwattx_fcmp.a)
    set(CARGO_TARGET_FLAG "")
endif()

set(RUST_LIB_PATH ${RUST_RELEASE_DIR}/${RUST_LIB_NAME})

# Custom target to build Rust library
add_custom_command(
    OUTPUT ${RUST_LIB_PATH}
    COMMAND ${CARGO_EXECUTABLE} build --release ${CARGO_TARGET_FLAG}
    WORKING_DIRECTORY ${RUST_DIR}
    COMMENT "Building FCMP Rust library..."
    DEPENDS
        ${RUST_DIR}/Cargo.toml
        ${RUST_DIR}/src/lib.rs
        ${RUST_DIR}/cbindgen.toml
)

add_custom_target(wattx_fcmp_rust
    DEPENDS ${RUST_LIB_PATH}
)

# Import the Rust static library
add_library(wattx_fcmp_ffi STATIC IMPORTED GLOBAL)
set_target_properties(wattx_fcmp_ffi PROPERTIES
    IMPORTED_LOCATION ${RUST_LIB_PATH}
)
add_dependencies(wattx_fcmp_ffi wattx_fcmp_rust)

# Platform-specific dependencies for Rust library
if(UNIX AND NOT APPLE)
    # Linux requires these for Rust crypto libraries
    find_package(Threads REQUIRED)
    target_link_libraries(wattx_fcmp_ffi INTERFACE
        Threads::Threads
        ${CMAKE_DL_LIBS}
        m
    )
elseif(APPLE)
    target_link_libraries(wattx_fcmp_ffi INTERFACE
        "-framework Security"
        "-framework CoreFoundation"
    )
elseif(WIN32)
    target_link_libraries(wattx_fcmp_ffi INTERFACE
        ws2_32
        bcrypt
        userenv
        ntdll
    )
endif()

# C++ wrapper library
add_library(wattx_fcmp STATIC
    fcmp_wrapper.cpp
)

target_include_directories(wattx_fcmp
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(wattx_fcmp
    PUBLIC
        wattx_fcmp_ffi
        wattx_privacy  # For ed25519 and curvetree
)

# Ensure Rust library is built before C++ compilation
add_dependencies(wattx_fcmp wattx_fcmp_rust)

# Export targets
set(WATTX_FCMP_LIBRARY wattx_fcmp PARENT_SCOPE)

message(STATUS "FCMP library enabled with Rust FFI")
