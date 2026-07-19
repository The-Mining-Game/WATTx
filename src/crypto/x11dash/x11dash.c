// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.
//
// Canonical Dash X11. Verified against the block-50 regtest header vector
// (66aff159...7c...0d6c) and BLAKE-512("") = a8cfbbd7..., matching dashd and
// x11-hash-js. Sub-hashes are the portable sphlib reference (dsph_* namespace).

#include "x11dash.h"

#include <string.h>

#include "dsph_blake.h"
#include "dsph_bmw.h"
#include "dsph_groestl.h"
#include "dsph_skein.h"
#include "dsph_jh.h"
#include "dsph_keccak.h"
#include "dsph_luffa.h"
#include "dsph_cubehash.h"
#include "dsph_shavite.h"
#include "dsph_simd.h"
#include "dsph_echo.h"

void x11_dash_hash(const void* input, size_t len, void* output)
{
    unsigned char hash[64];

    dsph_blake512_context ctx_blake;
    dsph_blake512_init(&ctx_blake);
    dsph_blake512(&ctx_blake, input, len);
    dsph_blake512_close(&ctx_blake, hash);

    dsph_bmw512_context ctx_bmw;
    dsph_bmw512_init(&ctx_bmw);
    dsph_bmw512(&ctx_bmw, hash, 64);
    dsph_bmw512_close(&ctx_bmw, hash);

    dsph_groestl512_context ctx_groestl;
    dsph_groestl512_init(&ctx_groestl);
    dsph_groestl512(&ctx_groestl, hash, 64);
    dsph_groestl512_close(&ctx_groestl, hash);

    dsph_skein512_context ctx_skein;
    dsph_skein512_init(&ctx_skein);
    dsph_skein512(&ctx_skein, hash, 64);
    dsph_skein512_close(&ctx_skein, hash);

    dsph_jh512_context ctx_jh;
    dsph_jh512_init(&ctx_jh);
    dsph_jh512(&ctx_jh, hash, 64);
    dsph_jh512_close(&ctx_jh, hash);

    dsph_keccak512_context ctx_keccak;
    dsph_keccak512_init(&ctx_keccak);
    dsph_keccak512(&ctx_keccak, hash, 64);
    dsph_keccak512_close(&ctx_keccak, hash);

    dsph_luffa512_context ctx_luffa;
    dsph_luffa512_init(&ctx_luffa);
    dsph_luffa512(&ctx_luffa, hash, 64);
    dsph_luffa512_close(&ctx_luffa, hash);

    dsph_cubehash512_context ctx_cubehash;
    dsph_cubehash512_init(&ctx_cubehash);
    dsph_cubehash512(&ctx_cubehash, hash, 64);
    dsph_cubehash512_close(&ctx_cubehash, hash);

    dsph_shavite512_context ctx_shavite;
    dsph_shavite512_init(&ctx_shavite);
    dsph_shavite512(&ctx_shavite, hash, 64);
    dsph_shavite512_close(&ctx_shavite, hash);

    dsph_simd512_context ctx_simd;
    dsph_simd512_init(&ctx_simd);
    dsph_simd512(&ctx_simd, hash, 64);
    dsph_simd512_close(&ctx_simd, hash);

    dsph_echo512_context ctx_echo;
    dsph_echo512_init(&ctx_echo);
    dsph_echo512(&ctx_echo, hash, 64);
    dsph_echo512_close(&ctx_echo, hash);

    memcpy(output, hash, 32);
}
