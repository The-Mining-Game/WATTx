// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.
//
// Recompute the go-ethereum ethash "seal hash" (the hash a miner actually
// solves) from a parent block header, so WATTx can bind an ethash AuxPoW proof
// to the parent header's extraData commitment — making ETC/Altcoinchain merged
// mining trustless instead of asserting the commitment pool-side.
//
// Seal hash = keccak256(RLP([ParentHash, UncleHash, Coinbase, Root, TxHash,
//   ReceiptHash, Bloom, Difficulty, Number, GasLimit, GasUsed, Time, Extra]
//   + [BaseFee if the chain is post-London])).  (geth consensus.go SealHash())

#ifndef WATTX_AUXPOW_ETHASH_SEAL_H
#define WATTX_AUXPOW_ETHASH_SEAL_H

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <ethash/keccak.h>

namespace ethseal {

// RLP integers are minimal big-endian (no leading zero bytes; 0 => empty).
inline std::vector<uint8_t> Minimal(const std::vector<uint8_t>& v) {
    size_t i = 0;
    while (i < v.size() && v[i] == 0) ++i;
    return std::vector<uint8_t>(v.begin() + i, v.end());
}

inline void RlpLen(std::vector<uint8_t>& out, size_t len, uint8_t short_base, uint8_t long_base) {
    if (len < 56) {
        out.push_back(static_cast<uint8_t>(short_base + len));
    } else {
        std::vector<uint8_t> lb;
        size_t x = len;
        while (x) { lb.push_back(static_cast<uint8_t>(x & 0xff)); x >>= 8; }
        std::reverse(lb.begin(), lb.end());
        out.push_back(static_cast<uint8_t>(long_base + lb.size()));
        out.insert(out.end(), lb.begin(), lb.end());
    }
}

// Encode a byte string as an RLP item.
inline void RlpStr(std::vector<uint8_t>& out, const uint8_t* d, size_t n) {
    if (n == 1 && d[0] < 0x80) {
        out.push_back(d[0]);
    } else {
        RlpLen(out, n, 0x80, 0xb7);
        out.insert(out.end(), d, d + n);
    }
}
inline void RlpStr(std::vector<uint8_t>& out, const std::vector<uint8_t>& v) {
    RlpStr(out, v.data(), v.size());
}

// Header fields in SealHash order. Hash/addr/bloom/extra are raw bytes;
// numeric fields are raw big-endian (minimal-ized here).
struct EthHeaderFields {
    std::vector<uint8_t> parentHash, uncleHash, coinbase, root, txHash, receiptHash, bloom, extra;
    std::vector<uint8_t> difficulty, number, gasLimit, gasUsed, time, baseFee;
    bool hasBaseFee{false};
};

// Returns the 32-byte seal hash.
inline std::array<uint8_t, 32> SealHash(const EthHeaderFields& h) {
    std::vector<uint8_t> payload;
    RlpStr(payload, h.parentHash);
    RlpStr(payload, h.uncleHash);
    RlpStr(payload, h.coinbase);
    RlpStr(payload, h.root);
    RlpStr(payload, h.txHash);
    RlpStr(payload, h.receiptHash);
    RlpStr(payload, h.bloom);
    RlpStr(payload, Minimal(h.difficulty));
    RlpStr(payload, Minimal(h.number));
    RlpStr(payload, Minimal(h.gasLimit));
    RlpStr(payload, Minimal(h.gasUsed));
    RlpStr(payload, Minimal(h.time));
    RlpStr(payload, h.extra);
    if (h.hasBaseFee) RlpStr(payload, Minimal(h.baseFee));

    std::vector<uint8_t> rlp;
    RlpLen(rlp, payload.size(), 0xc0, 0xf7);
    rlp.insert(rlp.end(), payload.begin(), payload.end());

    ethash_hash256 k = ethash_keccak256(rlp.data(), rlp.size());
    std::array<uint8_t, 32> out;
    std::memcpy(out.data(), k.bytes, 32);
    return out;
}

}  // namespace ethseal

#endif  // WATTX_AUXPOW_ETHASH_SEAL_H
