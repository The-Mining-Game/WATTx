# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Find liboqs for post-quantum cryptography (Dilithium/ML-DSA)
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(LIBOQS liboqs)
endif()

if(NOT LIBOQS_FOUND)
  find_library(LIBOQS_LIBRARIES NAMES oqs liboqs)
  find_path(LIBOQS_INCLUDE_DIRS oqs/oqs.h)
  if(LIBOQS_LIBRARIES AND LIBOQS_INCLUDE_DIRS)
    set(LIBOQS_FOUND TRUE)
  endif()
endif()

add_library(bitcoin_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  dilithium.cpp
  hex_base.cpp
  hkdf_sha256_32.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  muhash.cpp
  poly1305.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha256_sse4.cpp
  sha3.cpp
  sha512.cpp
  siphash.cpp
  ../support/cleanse.cpp
  # X25X multi-algorithm mining
  x25x/x25x.cpp
  # sphlib for X11 algorithm (X25X native PoW; non-canonical, self-consistent)
  sphlib/x11.c
  # Canonical Dash X11 for the X11 merged-mining parent path (dsph_* namespace).
  # aes_helper.c is #included by echo.c/shavite.c, so it is NOT listed here.
  x11dash/x11dash.c
  x11dash/blake.c
  x11dash/bmw.c
  x11dash/groestl.c
  x11dash/skein.c
  x11dash/jh.c
  x11dash/keccak.c
  x11dash/luffa.c
  x11dash/cubehash.c
  x11dash/shavite.c
  x11dash/simd.c
  x11dash/echo.c
  # Equihash for ZCash-compatible mining
  equihash/equihash.cpp
  equihash/equihash_canon.cpp
  # Canonical Kaspa kHeavyHash for the kaspa merged-mining parent path
  kheavyhash/kheavyhash.cpp
)

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
    ethash
    randomx
    libscrypt
    wattx_mining
)

# Link liboqs for post-quantum cryptography
if(LIBOQS_FOUND)
  target_include_directories(bitcoin_crypto PRIVATE ${LIBOQS_INCLUDE_DIRS})
  target_link_libraries(bitcoin_crypto PRIVATE ${LIBOQS_LIBRARIES})
  target_compile_definitions(bitcoin_crypto PRIVATE HAVE_LIBOQS)
  message(STATUS "liboqs found: Post-quantum cryptography (Dilithium) enabled")
else()
  message(WARNING "liboqs not found: Post-quantum cryptography (Dilithium) DISABLED")
endif()

if(HAVE_SSE41)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41)
  target_sources(bitcoin_crypto PRIVATE sha256_sse41.cpp)
  set_property(SOURCE sha256_sse41.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS}
  )
endif()

if(HAVE_AVX2)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_AVX2)
  target_sources(bitcoin_crypto PRIVATE sha256_avx2.cpp)
  set_property(SOURCE sha256_avx2.cpp PROPERTY
    COMPILE_OPTIONS ${AVX2_CXXFLAGS}
  )
endif()

if(HAVE_SSE41 AND HAVE_X86_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41 ENABLE_X86_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_x86_shani.cpp)
  set_property(SOURCE sha256_x86_shani.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS} ${X86_SHANI_CXXFLAGS}
  )
endif()

if(HAVE_ARM_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_ARM_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_arm_shani.cpp)
  set_property(SOURCE sha256_arm_shani.cpp PROPERTY
    COMPILE_OPTIONS ${ARM_SHANI_CXXFLAGS}
  )
endif()
