// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.
//
// Canonical Dash X11 (blake-bmw-groestl-skein-jh-keccak-luffa-cubehash-
// shavite-simd-echo) for the X11 merged-mining PARENT path. This matches
// dashd / x11-hash-js exactly, unlike src/crypto/sphlib/x11.c whose sphlib is
// non-canonical (kept only for X25X's self-consistent native PoW). The sub-hash
// symbols here are namespaced dsph_* so both coexist without collision.

#ifndef BITCOIN_CRYPTO_X11DASH_X11DASH_H
#define BITCOIN_CRYPTO_X11DASH_X11DASH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute canonical Dash X11 of `len` bytes at `input`, writing 32 bytes to
// `output` (natural sphlib order, same as dashd's HashX11 internal uint256).
void x11_dash_hash(const void* input, size_t len, void* output);

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_CRYPTO_X11DASH_X11DASH_H
