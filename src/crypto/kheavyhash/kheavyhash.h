// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.
//
// Canonical Kaspa kHeavyHash + block/tx hashing primitives for the kaspa
// merged-mining parent path. Ports of rusty-kaspa v2.x reference code:
//   PoW        consensus/pow/src/lib.rs      (cSHAKE256 "ProofOfWorkHash" ->
//              heavy matrix multiply -> cSHAKE256 "HeavyHash")
//   matrix     consensus/pow/src/{matrix,xoshiro}.rs
//   hashing    keyed blake2b-256 domains "BlockHash" / "TransactionHash" /
//              "MerkleBranchHash" (crypto/hashes/src/hashers.rs)
// Validated against a live kaspad: the JS twin of this port (tools/kaspa_lib.js)
// solved a block kaspad ACCEPTED, and its computed header hash was the DAG tip.

#ifndef WATTX_CRYPTO_KHEAVYHASH_H
#define WATTX_CRYPTO_KHEAVYHASH_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace kheavyhash {

// keyed blake2b-256 over data (key = ASCII domain string, e.g. "BlockHash")
void Blake2bKeyed(const char* key, const uint8_t* data, size_t len, uint8_t out[32]);

// Full kaspa PoW for one attempt: pre_pow_hash (BlockHash of the header with
// nonce=0, timestamp=0), the header's REAL timestamp (ms) and nonce.
// out is the 32-byte pow hash; kaspa compares it little-endian vs target —
// the same convention as WATTx's UintToArith256, so no byte reversal needed.
void Pow(const uint8_t pre_pow[32], uint64_t timestamp, uint64_t nonce, uint8_t out[32]);

// Field offsets inside a kaspa BlockHash preimage (the exact byte string keyed
// blake2b hashes). Layout: u16 version | u64 num_levels | per level (u64 count
// + 32B x count) | 3 x 32B roots | u64 timestamp | u32 bits | u64 nonce |
// u64 daa_score | u64 blue_score | u64 bw_len + bw | 32B pruning_point.
struct HeaderPreimageInfo {
    size_t merkle_root_off{0};
    size_t ts_off{0};
    size_t nonce_off{0};
};

// Structural parse + exact-length validation. Returns false on malformed input.
bool ParseHeaderPreimage(const uint8_t* d, size_t len, HeaderPreimageInfo& out);

// PoW straight from a preimage carrying the real nonce+timestamp: zeroes the
// two fields for the pre-pow hash, then runs Pow() with the real values.
bool PowFromPreimage(const std::vector<uint8_t>& preimage, uint8_t out[32]);

// Header hash (block hash) of a preimage as-is.
void HeaderHash(const uint8_t* preimage, size_t len, uint8_t out[32]);

// TransactionHash of a serialized kaspa transaction (tx.rs FULL encoding).
void TransactionHash(const uint8_t* data, size_t len, uint8_t out[32]);

// Fold a leaf hash up the merkle tree ("MerkleBranchHash" keyed blake2b pairs).
// index selects left/right per level (coinbase = 0 -> always left).
void MerkleFold(const uint8_t leaf[32],
                const std::vector<std::vector<uint8_t>>& branch,
                uint32_t index, uint8_t out[32]);

}  // namespace kheavyhash

#endif  // WATTX_CRYPTO_KHEAVYHASH_H
