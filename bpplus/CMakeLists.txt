# libwattx_bpplus — ported Monero Bulletproofs+ (audited ed25519 range proofs).
#
# Deliberately a TOP-LEVEL directory (not under src/) so it does NOT inherit
# src/'s global include_directories: this tree ships its own span.h, crypto/*,
# ringct/* headers (Monero/epee) that collide by name with Bitcoin Core's. Here,
# only this directory's own includes are on the path, so the Monero headers win.
#
# EXCLUDE_FROM_ALL: builds only on demand (cmake --build --target wattx_bpplus /
# test_bpplus); nothing links it into wattxd yet, so it cannot affect the daemon.
# When wired into consensus it will be exposed via a single byte-buffer wrapper
# (no rct:: types leaked) to avoid symbol/type collisions with bitcoin_crypto.

# The project is LANGUAGES NONE and enables C only inside src/ (directory-scoped),
# so enable it here too — this directory has .c crypto sources.
enable_language(C)

add_library(wattx_bpplus STATIC EXCLUDE_FROM_ALL
    crypto/crypto-ops.c
    crypto/crypto-ops-data.c
    crypto/keccak.c
    ringct/rctCryptoOps.c
    common/aligned.c
    ringct/rctTypes.cpp
    ringct/rctOps.cpp
    ringct/multiexp.cc
    ringct/bulletproofs_plus.cc
    bpplus_support.cpp
    bpplus_api.cpp
)

# PRIVATE: internal Monero/epee headers (span.h, crypto/*, ringct/*) used only to
# BUILD the lib. INTERFACE: only include/ (bpplus_api.h) is exposed to consumers, so
# linking wattx_bpplus into src/ code does NOT drag the colliding headers onto their
# include path.
target_include_directories(wattx_bpplus
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/ringct
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# crypto/warnings.h needs <boost/preprocessor/stringize.hpp>. On Linux the system
# boost hides this; cross builds (mingw depends) must get it from Boost explicitly.
find_package(Boost QUIET)
if(Boost_FOUND)
    target_include_directories(wattx_bpplus PRIVATE ${Boost_INCLUDE_DIRS})
endif()

set_target_properties(wattx_bpplus PROPERTIES
    C_STANDARD 11
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)

# crypto/int-util.h needs BYTE_ORDER/LITTLE_ENDIAN from <endian.h>, which glibc
# only exposes under __USE_MISC -- i.e. with GNU extensions on. C_STANDARD 11
# selects strict -std=c11, so on toolchains that do not enable them by default
# (notably the aarch64-linux-gnu cross compiler) the build dies on
# 'static assertion failed: "BYTE_ORDER is undefined"'. Ask for them explicitly.
target_compile_definitions(wattx_bpplus PRIVATE _GNU_SOURCE)

# In-tree tests use rct:: directly, so they need the INTERNAL headers too.
set(_bpplus_internal_inc
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/ringct
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Standalone prove/verify test for the port.
add_executable(test_bpplus EXCLUDE_FROM_ALL test/bpplus_test.cpp)
target_link_libraries(test_bpplus PRIVATE wattx_bpplus)
target_include_directories(test_bpplus PRIVATE ${_bpplus_internal_inc})
set_target_properties(test_bpplus PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

# Byte-buffer wrapper API test (prove -> verify through the clean public interface).
add_executable(test_bpplus_api EXCLUDE_FROM_ALL test/bpplus_api_test.cpp)
target_link_libraries(test_bpplus_api PRIVATE wattx_bpplus)
target_include_directories(test_bpplus_api PRIVATE ${_bpplus_internal_inc})
set_target_properties(test_bpplus_api PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
