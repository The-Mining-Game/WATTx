# Copyright (c) 2024-2026 The WATTx Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Privacy module for WATTx
# Implements stealth addresses, ring signatures, confidential transactions,
# and FCMP (Full-Chain Membership Proofs) support

# Find libsodium for Ed25519 cryptographic operations
if(CMAKE_CROSSCOMPILING AND EXISTS "${CMAKE_FIND_ROOT_PATH}/include/sodium.h")
    # Cross-compilation: use libsodium from depends directory
    set(SODIUM_INCLUDE_DIRS "${CMAKE_FIND_ROOT_PATH}/include")
    set(SODIUM_LIBRARIES "${CMAKE_FIND_ROOT_PATH}/lib/libsodium.a")
    set(SODIUM_CFLAGS_OTHER "")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
endif()

add_library(wattx_privacy STATIC
    stealth.cpp
    ring_signature.cpp
    confidential.cpp
    privacy.cpp
    consensus.cpp
    p2p.cpp
    # FCMP transaction types
    fcmp_tx.cpp
    # FCMP consensus integration
    fcmp_consensus.cpp
    # Ed25519 module for FCMP
    ed25519/ed25519_ops.cpp
    ed25519/pedersen.cpp
    # Curve tree module for FCMP
    curvetree/curve_tree.cpp
    curvetree/tree_db.cpp
)

target_include_directories(wattx_privacy
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(wattx_privacy
    PUBLIC
        bitcoin_crypto
        secp256k1
        bitcoin_common
        leveldb
        ${SODIUM_LIBRARIES}
)

# Add Boost include directory for headers used transitively (e.g. eth_client/FixedHash.h)
target_include_directories(wattx_privacy PUBLIC ${Boost_INCLUDE_DIR})

# MinGW cross-compilation: -std=c++20 strips the predefined WIN32 macro,
# but Bitcoin Core headers (fs.h, etc.) check #ifdef WIN32.
# WIN32_LEAN_AND_MEAN prevents windows.h from including nb30.h which
# redefines UNIQUE_NAME (conflicts with util/macros.h used by sync.h LOCK).
if(MINGW)
    target_compile_definitions(wattx_privacy PUBLIC WIN32 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

target_compile_options(wattx_privacy PRIVATE ${SODIUM_CFLAGS_OTHER})

# Ed25519 standalone test executable
add_executable(test_ed25519
    ed25519/ed25519_tests.cpp
    ed25519/ed25519_ops.cpp
    ed25519/pedersen.cpp
)

target_include_directories(test_ed25519
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(test_ed25519
    PRIVATE
        bitcoin_crypto
        ${SODIUM_LIBRARIES}
)

target_compile_options(test_ed25519 PRIVATE ${SODIUM_CFLAGS_OTHER})

# Curve tree standalone test executable
add_executable(test_curvetree
    curvetree/curvetree_tests.cpp
    curvetree/curve_tree.cpp
    curvetree/tree_db.cpp
    ed25519/ed25519_ops.cpp
    ed25519/pedersen.cpp
)

target_include_directories(test_curvetree
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(test_curvetree
    PRIVATE
        bitcoin_crypto
        leveldb
        ${SODIUM_LIBRARIES}
)

target_compile_options(test_curvetree PRIVATE ${SODIUM_CFLAGS_OTHER})

# Optional: Bulletproofs library for efficient range proofs
# find_package(Bulletproofs)
# if(Bulletproofs_FOUND)
#     target_link_libraries(wattx_privacy PRIVATE Bulletproofs::bulletproofs)
#     target_compile_definitions(wattx_privacy PRIVATE HAVE_BULLETPROOFS)
# endif()

# FCMP Rust FFI library
add_subdirectory(fcmp)

if(WATTX_FCMP_ENABLED)
    # Add FCMP wrapper to the privacy library dependencies
    target_link_libraries(wattx_privacy PUBLIC wattx_fcmp)
    target_compile_definitions(wattx_privacy PUBLIC HAVE_FCMP)

    # FCMP test executable
    add_executable(test_fcmp
        fcmp/fcmp_tests.cpp
    )

    target_include_directories(test_fcmp
        PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${SODIUM_INCLUDE_DIRS}
    )

    target_link_libraries(test_fcmp
        PRIVATE
            wattx_fcmp
            wattx_privacy
            bitcoin_crypto
            leveldb
            ${SODIUM_LIBRARIES}
            $<$<BOOL:${WIN32}>:ntdll>
    )

    target_compile_options(test_fcmp PRIVATE ${SODIUM_CFLAGS_OTHER})
endif()
