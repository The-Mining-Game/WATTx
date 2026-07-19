// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_X11_H
#define WATTX_STRATUM_PARENT_CHAIN_X11_H

#include <stratum/parent_chain_bitcoin.h>
#include <arith_uint256.h>

// Canonical Dash X11 (matches dashd/x11-hash-js) — the merged-mining parent
// path must agree with the real Dash daemon, NOT src/crypto/sphlib/x11.c whose
// sphlib is non-canonical (that one stays reserved for X25X's native PoW).
#include <crypto/x11dash/x11dash.h>

namespace merged_stratum {

/**
 * X11 block header (same structure as Bitcoin, but uses X11 PoW)
 */
class X11BlockHeader : public BitcoinBlockHeader {
public:
    uint256 GetPoWHash() const override {
        // X11 is a chain of 11 hashing algorithms
        std::vector<uint8_t> header_data = Serialize();

        uint256 hash;
        x11_dash_hash(header_data.data(), header_data.size(), hash.data());

        return hash;
    }
};

/**
 * Dash/X11 parent chain handler
 */
class DashChainHandler : public BitcoinChainHandler {
public:
    explicit DashChainHandler(const ParentChainConfig& config)
        : BitcoinChainHandler(config) {}

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& /* seed_hash */
    ) override {
        uint256 hash;
        x11_dash_hash(hashing_blob.data(), hashing_blob.size(), hash.data());
        return hash;
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<X11BlockHeader>();
        header->nVersion = m_current_header.nVersion;
        header->hashPrevBlock = m_current_header.hashPrevBlock;
        header->hashMerkleRoot = coinbase_data.merkle_root;
        header->nTime = m_current_header.nTime;
        header->nBits = m_current_header.nBits;
        header->nNonce = nonce;
        return header;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& extra_data = ""
    ) override {
        CAuxPow proof = BitcoinChainHandler::CreateAuxPow(
            wattx_header, coinbase_data, nonce, merge_mining_tag, extra_data);
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::X11);
        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        if (difficulty == 0) difficulty = 1;
        arith_uint256 max_target;
        max_target.SetCompact(0x1e0ffff0);
        arith_uint256 target = max_target / difficulty;
        return ArithToUint256(target);
    }

private:
    X11BlockHeader m_current_header;
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_X11_H
