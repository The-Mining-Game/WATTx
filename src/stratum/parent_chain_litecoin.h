// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_LITECOIN_H
#define WATTX_STRATUM_PARENT_CHAIN_LITECOIN_H

#include <stratum/parent_chain_bitcoin.h>
#include <arith_uint256.h>
#include <eth_client/utils/libscrypt/libscrypt.h>

namespace merged_stratum {

/**
 * Litecoin block header (same structure as Bitcoin, but uses Scrypt PoW)
 */
class LitecoinBlockHeader : public BitcoinBlockHeader {
public:
    uint256 GetPoWHash() const override {
        // Litecoin uses Scrypt with N=1024, r=1, p=1
        std::vector<uint8_t> header_data = Serialize();

        uint256 hash;
        // scrypt(password, salt, N, r, p, output_len)
        // For Litecoin: N=1024, r=1, p=1
        libscrypt_scrypt(
            header_data.data(), header_data.size(),  // password
            header_data.data(), header_data.size(),  // salt (same as password)
            1024, 1, 1,                               // N, r, p
            hash.data(), 32                           // output
        );

        return hash;
    }
};

/**
 * Litecoin/Scrypt parent chain handler
 * Supports Litecoin, Dogecoin, and other Scrypt-based chains
 */
class LitecoinChainHandler : public BitcoinChainHandler {
public:
    explicit LitecoinChainHandler(const ParentChainConfig& config)
        : BitcoinChainHandler(config) {
        // Litecoin uses same RPC interface as Bitcoin
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& /* seed_hash */
    ) override {
        // Scrypt with N=1024, r=1, p=1
        uint256 hash;
        libscrypt_scrypt(
            hashing_blob.data(), hashing_blob.size(),
            hashing_blob.data(), hashing_blob.size(),
            1024, 1, 1,
            hash.data(), 32
        );
        return hash;
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<LitecoinBlockHeader>();
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
        // Override algo to Scrypt so GetParentBlockPoWHash() uses scrypt()
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::SCRYPT);
        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        if (difficulty == 0) difficulty = 1;
        arith_uint256 max_target;
        max_target.SetCompact(0x1e0ffff0);  // Litecoin's max target
        arith_uint256 target = max_target / difficulty;
        return ArithToUint256(target);
    }

protected:
    // litecoind refuses getblocktemplate unless the client claims mweb support
    std::string GetGbtRules() const override { return "[\"segwit\",\"mweb\"]"; }

private:
    LitecoinBlockHeader m_current_header;
};

/**
 * Dogecoin handler (same as Litecoin but different chain params)
 */
class DogecoinChainHandler : public LitecoinChainHandler {
public:
    explicit DogecoinChainHandler(const ParentChainConfig& config)
        : LitecoinChainHandler(config) {}

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        // Dogecoin uses same Scrypt parameters but different genesis
        if (difficulty == 0) difficulty = 1;

        arith_uint256 max_target;
        max_target.SetCompact(0x1e0ffff0);
        arith_uint256 target = max_target / difficulty;
        return ArithToUint256(target);
    }
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_LITECOIN_H
