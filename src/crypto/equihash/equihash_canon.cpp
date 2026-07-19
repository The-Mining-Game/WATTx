// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.
//
// Canonical Equihash validator. See equihash_canon.h. Blake2b from randomx.

#include <crypto/equihash/equihash_canon.h>

#include <randomx/src/blake2/blake2.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace equihash_canon {
namespace {

inline uint32_t be32(const unsigned char* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline void put_be32(uint32_t v, unsigned char* p) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

// Zcash ExpandArray: unpack bit_len-bit big-endian words into
// (byte_pad + ceil(bit_len/8))-byte output slots.
void ExpandArray(const unsigned char* in, size_t in_len,
                 unsigned char* out, size_t bit_len, size_t byte_pad) {
    const size_t out_width = (bit_len + 7) / 8 + byte_pad;
    const uint32_t bit_len_mask = (uint32_t(1) << bit_len) - 1;
    size_t acc_bits = 0, j = 0;
    uint32_t acc_value = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc_value = (acc_value << 8) | in[i];
        acc_bits += 8;
        if (acc_bits >= bit_len) {
            acc_bits -= bit_len;
            for (size_t x = 0; x < byte_pad; x++) out[j + x] = 0;
            for (size_t x = byte_pad; x < out_width; x++) {
                out[j + x] = (acc_value >> (acc_bits + 8 * (out_width - x - 1)))
                             & ((bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF);
            }
            j += out_width;
        }
    }
}

void InitState(blake2b_state* st, unsigned int n, unsigned int k,
               const unsigned char* input, size_t input_len) {
    blake2b_param P;
    std::memset(&P, 0, sizeof(P));
    P.digest_length = static_cast<uint8_t>((512 / n) * n / 8);  // HashOutput
    P.fanout = 1;
    P.depth = 1;
    // BitcoinZ personalizes 144,5 as "BitcoinZ"; Zcash 200,9 and regtest 48,5
    // use "ZcashPoW" (matches btcz/bitcoinz InitialiseState).
    const char* pers = (n == 144 && k == 5) ? "BitcoinZ" : "ZcashPoW";
    std::memcpy(P.personal, pers, 8);
    const uint32_t le_n = n, le_k = k;  // little-endian target
    std::memcpy(P.personal + 8, &le_n, 4);
    std::memcpy(P.personal + 12, &le_k, 4);
    blake2b_init_param(st, &P);
    blake2b_update(st, input, input_len);
}

} // namespace

bool Verify(unsigned int n, unsigned int k,
            const unsigned char* input, size_t input_len,
            const unsigned char* solution, size_t solution_len) {
    if (n == 0 || k == 0 || (n % 8) != 0 || n <= k) return false;
    const size_t IPH           = 512 / n;
    if (IPH == 0) return false;
    const size_t hashOutput    = IPH * n / 8;
    const size_t collisionBit  = n / (k + 1);
    const size_t collisionByte = (collisionBit + 7) / 8;
    const size_t hashLength0   = (k + 1) * collisionByte;
    const size_t numIndices    = size_t(1) << k;
    const size_t solutionWidth = numIndices * (collisionBit + 1) / 8;
    if (solution_len != solutionWidth) return false;

    blake2b_state base;
    InitState(&base, n, k, input, input_len);

    // GetIndicesFromMinimal: expand the compressed solution into 2^k indices.
    const size_t bitLen = collisionBit + 1;
    const size_t bytePad = sizeof(uint32_t) - (bitLen + 7) / 8;
    std::vector<unsigned char> idxArr(numIndices * sizeof(uint32_t));
    ExpandArray(solution, solution_len, idxArr.data(), bitLen, bytePad);

    // Initial step rows: [expanded hash (hashLength0)] ++ [index big-endian32].
    std::vector<std::vector<unsigned char>> X;
    X.reserve(numIndices);
    std::vector<unsigned char> tmp(hashOutput);
    for (size_t r = 0; r < numIndices; r++) {
        const uint32_t i = be32(idxArr.data() + r * sizeof(uint32_t));
        blake2b_state st = base;
        const uint32_t g = i / IPH;  // fed little-endian
        blake2b_update(&st, reinterpret_cast<const unsigned char*>(&g), 4);
        blake2b_final(&st, tmp.data(), hashOutput);
        std::vector<unsigned char> row(hashLength0 + 4);
        ExpandArray(tmp.data() + (i % IPH) * (n / 8), n / 8, row.data(), collisionBit, 0);
        put_be32(i, row.data() + hashLength0);
        X.push_back(std::move(row));
    }

    size_t hashLen = hashLength0;
    size_t lenIndices = 4;
    while (X.size() > 1) {
        if (X.size() % 2 != 0) return false;
        std::vector<std::vector<unsigned char>> Xc;
        Xc.reserve(X.size() / 2);
        for (size_t i = 0; i < X.size(); i += 2) {
            const auto& a = X[i];
            const auto& b = X[i + 1];
            // collision on the first collisionByte bytes
            if (std::memcmp(a.data(), b.data(), collisionByte) != 0) return false;
            // ordering: reject b.indices < a.indices (require a before b)
            if (std::memcmp(b.data() + hashLen, a.data() + hashLen, lenIndices) < 0) return false;
            // distinct indices between the two subtrees
            for (size_t p = 0; p < lenIndices; p += 4)
                for (size_t q = 0; q < lenIndices; q += 4)
                    if (std::memcmp(a.data() + hashLen + p, b.data() + hashLen + q, 4) == 0) return false;
            // merge: XOR beyond the collision, then a's indices, then b's
            std::vector<unsigned char> row((hashLen - collisionByte) + 2 * lenIndices);
            for (size_t j = collisionByte; j < hashLen; j++)
                row[j - collisionByte] = a[j] ^ b[j];
            std::memcpy(row.data() + (hashLen - collisionByte), a.data() + hashLen, lenIndices);
            std::memcpy(row.data() + (hashLen - collisionByte) + lenIndices, b.data() + hashLen, lenIndices);
            Xc.push_back(std::move(row));
        }
        X = std::move(Xc);
        hashLen -= collisionByte;
        lenIndices *= 2;
    }
    if (X.size() != 1) return false;
    for (size_t i = 0; i < hashLen; i++)
        if (X[0][i] != 0) return false;
    return true;
}

} // namespace equihash_canon
