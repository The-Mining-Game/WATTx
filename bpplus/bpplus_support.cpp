// Leaf support functions for the isolated libwattx_bpplus port — provided here so
// we don't have to pull Monero's crypto.cpp/hash.c (which snowball into the epee/
// cryptonote random pool + slow-hash). All are standard, self-contained.
#include <cstdint>
#include <cstddef>
#include <fstream>
extern "C" {
#include "crypto/crypto-ops.h"
}
#include "crypto/keccak.h"

extern "C" {
// ref10 constant-time 32-byte compare: returns 0 iff x==y, -1 otherwise.
// differentbits is an OR of per-byte XORs, so it stays in [0,255].
int crypto_verify_32(const unsigned char *x, const unsigned char *y) {
    unsigned int differentbits = 0;
    for (int i = 0; i < 32; i++) differentbits |= (unsigned int)(x[i] ^ y[i]);
    return (int)((1 & ((differentbits - 1) >> 8)) - 1);
}

// C-linkage cn_fast_hash (declared in hash-ops.h, used by ringct/BP+).
void cn_fast_hash(const void *data, size_t length, char *hash) {
    keccak((const uint8_t *)data, length, (uint8_t *)hash, 32);
}
} // extern "C"

namespace crypto {

// keccak (Monero's cn_fast_hash) of arbitrary data → 32-byte output.
void cn_fast_hash(const void *data, std::size_t length, char *hash) {
    keccak((const uint8_t *)data, length, (uint8_t *)hash, 32);
}

// little-endian 32-byte < comparison (Monero's less32).
static bool less32(const unsigned char *k0, const unsigned char *k1) {
    for (int n = 31; n >= 0; --n) {
        if (k0[n] < k1[n]) return true;
        if (k0[n] > k1[n]) return false;
    }
    return false;
}

// Uniform scalar in [1, l) via rejection sampling, matching Monero's
// random32_unbiased. Uses /dev/urandom for cryptographic randomness.
void random32_unbiased(unsigned char *bytes) {
    static const unsigned char limit[32] = {
        0xe3,0x6a,0x67,0x72,0x8b,0xce,0x13,0x29,0x8f,0x30,0x82,0x8c,0x0b,0xa4,0x10,0x39,
        0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xf0 };
    std::ifstream urand("/dev/urandom", std::ios::binary);
    while (true) {
        urand.read((char *)bytes, 32);
        if (!less32(bytes, limit)) continue;
        sc_reduce32(bytes);
        if (sc_isnonzero(bytes)) break;
    }
}

} // namespace crypto
