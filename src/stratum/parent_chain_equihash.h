// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_EQUIHASH_H
#define WATTX_STRATUM_PARENT_CHAIN_EQUIHASH_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>

// Forward declaration - equihash verification
namespace equihash {
    bool Verify(unsigned int n, unsigned int k,
                const uint8_t* header, size_t header_len,
                const uint8_t* solution, size_t solution_len);
}

namespace merged_stratum {

/**
 * Zcash/Equihash block header (140 bytes + solution)
 */
class EquihashBlockHeader : public IParentBlockHeader {
public:
    int32_t nVersion{0};
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashReserved;      // Zcash-specific: commitment to sprout note commitments
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint256 nNonce;            // 256-bit nonce for Equihash
    std::vector<uint8_t> nSolution;  // Equihash solution

    uint256 GetHash() const override {
        // SHA256d of header + solution
        std::vector<uint8_t> data = Serialize();
        return Hash(data);
    }

    uint256 GetPoWHash() const override {
        // For Equihash, the PoW is verified differently
        // The hash is the block hash, solution validity is checked separately
        return GetHash();
    }

    std::vector<uint8_t> Serialize() const override {
        std::vector<uint8_t> data;
        data.reserve(140 + nSolution.size());

        // Version (4 bytes)
        data.push_back(nVersion & 0xFF);
        data.push_back((nVersion >> 8) & 0xFF);
        data.push_back((nVersion >> 16) & 0xFF);
        data.push_back((nVersion >> 24) & 0xFF);

        // Previous block hash (32 bytes)
        data.insert(data.end(), hashPrevBlock.begin(), hashPrevBlock.end());

        // Merkle root (32 bytes)
        data.insert(data.end(), hashMerkleRoot.begin(), hashMerkleRoot.end());

        // Reserved hash (32 bytes) - Zcash specific
        data.insert(data.end(), hashReserved.begin(), hashReserved.end());

        // Time (4 bytes)
        data.push_back(nTime & 0xFF);
        data.push_back((nTime >> 8) & 0xFF);
        data.push_back((nTime >> 16) & 0xFF);
        data.push_back((nTime >> 24) & 0xFF);

        // Bits (4 bytes)
        data.push_back(nBits & 0xFF);
        data.push_back((nBits >> 8) & 0xFF);
        data.push_back((nBits >> 16) & 0xFF);
        data.push_back((nBits >> 24) & 0xFF);

        // Nonce (32 bytes)
        data.insert(data.end(), nNonce.begin(), nNonce.end());

        // Solution (variable, typically 1344 bytes for Zcash)
        // Prepend compact size
        if (nSolution.size() < 253) {
            data.push_back(static_cast<uint8_t>(nSolution.size()));
        } else if (nSolution.size() <= 0xFFFF) {
            data.push_back(253);
            data.push_back(nSolution.size() & 0xFF);
            data.push_back((nSolution.size() >> 8) & 0xFF);
        }
        data.insert(data.end(), nSolution.begin(), nSolution.end());

        return data;
    }

    // Get header without solution for Equihash input
    std::vector<uint8_t> GetEquihashInput() const {
        std::vector<uint8_t> data;
        data.reserve(140);

        // Same as Serialize but without solution
        data.push_back(nVersion & 0xFF);
        data.push_back((nVersion >> 8) & 0xFF);
        data.push_back((nVersion >> 16) & 0xFF);
        data.push_back((nVersion >> 24) & 0xFF);

        data.insert(data.end(), hashPrevBlock.begin(), hashPrevBlock.end());
        data.insert(data.end(), hashMerkleRoot.begin(), hashMerkleRoot.end());
        data.insert(data.end(), hashReserved.begin(), hashReserved.end());

        data.push_back(nTime & 0xFF);
        data.push_back((nTime >> 8) & 0xFF);
        data.push_back((nTime >> 16) & 0xFF);
        data.push_back((nTime >> 24) & 0xFF);

        data.push_back(nBits & 0xFF);
        data.push_back((nBits >> 8) & 0xFF);
        data.push_back((nBits >> 16) & 0xFF);
        data.push_back((nBits >> 24) & 0xFF);

        data.insert(data.end(), nNonce.begin(), nNonce.end());

        return data;
    }

    uint32_t GetNonce() const override {
        // Return lower 32 bits of 256-bit nonce
        return nNonce.IsNull() ? 0 :
            (nNonce.data()[0] | (nNonce.data()[1] << 8) |
             (nNonce.data()[2] << 16) | (nNonce.data()[3] << 24));
    }

    void SetNonce(uint32_t nonce) override {
        // Set lower 32 bits
        nNonce.SetNull();
        nNonce.data()[0] = nonce & 0xFF;
        nNonce.data()[1] = (nonce >> 8) & 0xFF;
        nNonce.data()[2] = (nonce >> 16) & 0xFF;
        nNonce.data()[3] = (nonce >> 24) & 0xFF;
    }

    void SetNonce256(const uint256& nonce256) {
        nNonce = nonce256;
    }
};

/**
 * Zcash/Equihash parent chain handler
 * Equihash parameters: n=200, k=9 for Zcash
 */
class EquihashChainHandler : public ParentChainHandlerBase {
public:
    explicit EquihashChainHandler(const ParentChainConfig& config)
        : ParentChainHandlerBase(config),
          m_equihash_n(200), m_equihash_k(9) {}

    // Allow custom Equihash parameters (for Horizen, etc.)
    void SetEquihashParams(unsigned int n, unsigned int k) {
        m_equihash_n = n;
        m_equihash_k = k;
    }

    bool GetBlockTemplate(
        std::string& hashing_blob,
        std::string& full_template,
        std::string& seed_hash,
        uint64_t& height,
        uint64_t& difficulty,
        ParentCoinbaseData& coinbase_data
    ) override {
        // Zcash uses getblocktemplate like Bitcoin
        std::string response = JsonRpcCall("getblocktemplate", "[]");

        if (response.empty()) {
            LogPrintf("EquihashChain: Failed to get block template\n");
            return false;
        }

        // Parse response
        std::string version_str = ParseJsonString(response, "version");
        std::string prevhash = ParseJsonString(response, "previousblockhash");
        std::string bits_str = ParseJsonString(response, "bits");
        std::string height_str = ParseJsonString(response, "height");
        std::string curtime_str = ParseJsonString(response, "curtime");
        std::string finalsaplingroothash = ParseJsonString(response, "finalsaplingroothash");

        if (prevhash.empty()) {
            LogPrintf("EquihashChain: Invalid block template response\n");
            return false;
        }

        height = height_str.empty() ? 0 : std::stoull(height_str);
        m_current_height = height;

        // Build header
        m_current_header.nVersion = version_str.empty() ? 4 : std::stoi(version_str);
        m_current_header.hashPrevBlock = uint256::FromHex(prevhash).value_or(uint256{});
        m_current_header.nTime = curtime_str.empty() ? GetTime() : std::stoul(curtime_str);
        m_current_header.nBits = bits_str.empty() ? 0 : std::stoul(bits_str, nullptr, 16);

        // hashReserved contains sapling root for Zcash
        if (!finalsaplingroothash.empty()) {
            m_current_header.hashReserved = uint256::FromHex(finalsaplingroothash).value_or(uint256{});
        }

        // Build hashing blob (140 bytes without solution)
        auto header_data = m_current_header.GetEquihashInput();
        hashing_blob = HexStr(header_data);

        full_template = response;
        seed_hash = "";

        // Calculate difficulty
        difficulty = 1;  // TODO: proper calculation from bits

        LogPrintf("EquihashChain: Got template at height %lu\n", height);
        return true;
    }

    bool ParseBlockTemplate(
        const std::string& template_blob,
        ParentCoinbaseData& coinbase_data
    ) override {
        std::vector<uint8_t> data = ParseHex(template_blob);
        if (data.size() < 140) return false;

        // Zcash block structure is similar to Bitcoin
        // Parse coinbase from transactions
        // ... (similar to Bitcoin implementation)

        return true;
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& /*coinbase_data*/,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        // Commit the mined 140-byte header to the synthetic coinbase that carries
        // the WATTx merge-mining tag; CreateAuxPow rebuilds the identical coinbase
        // so the proof reproduces this exact merkle root (single-tx tree).
        CMutableTransaction cb = BuildAuxMergedCoinbase(merge_mining_tag, m_current_height);
        EquihashBlockHeader header = m_current_header;
        header.hashMerkleRoot = CTransaction(cb).GetHash();
        return HexStr(header.GetEquihashInput());
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& /* seed_hash */
    ) override {
        // For Equihash, the "PoW hash" is the block hash
        // Actual PoW verification requires checking the solution
        return Hash(hashing_blob);
    }

    bool VerifyEquihashSolution(
        const std::vector<uint8_t>& header_data,
        const std::vector<uint8_t>& solution
    ) {
        // Verify Equihash solution using the crypto library
        return equihash::Verify(m_equihash_n, m_equihash_k,
                                header_data.data(), header_data.size(),
                                solution.data(), solution.size());
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<EquihashBlockHeader>(m_current_header);
        header->hashMerkleRoot = coinbase_data.merkle_root;
        header->SetNonce(nonce);
        return header;
    }

    bool SubmitBlock(const std::string& block_blob) override {
        std::string response = JsonRpcCall("submitblock", "[\"" + block_blob + "\"]");
        return response.find("\"result\":null") != std::string::npos;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& /*extra_data*/ = ""
    ) override {
        CAuxPow proof;

        // Rebuild the SAME synthetic coinbase the miner committed to, so its txid
        // is the single-tx merkle root of both the mined header and the proof.
        CMutableTransaction cb = BuildAuxMergedCoinbase(merge_mining_tag, m_current_height);
        uint256 merkle_root = CTransaction(cb).GetHash();

        EquihashBlockHeader parent_header = m_current_header;
        parent_header.hashMerkleRoot = merkle_root;
        parent_header.SetNonce(nonce);

        // parentBlock: merkle_root for Check(), timestamp for time validation
        proof.parentBlock.timestamp   = parent_header.nTime;
        proof.parentBlock.merkle_root = merkle_root;

        // Raw 140-byte Equihash header (without solution) for SHA256d PoW check
        proof.parentAlgoId    = static_cast<uint8_t>(AuxPowAlgo::EQUIHASH);
        proof.parentHeaderRaw = parent_header.GetEquihashInput();  // 140-byte header only

        proof.coinbaseTxMut = cb;
        proof.coinbaseBranch.vHash.clear();
        proof.coinbaseBranch.nIndex = 0;
        proof.nChainId = m_config.chain_id;

        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        if (difficulty == 0) difficulty = 1;

        // Zcash difficulty calculation
        arith_uint256 max_target;
        max_target.SetCompact(0x1f07ffff);  // Zcash's initial target
        arith_uint256 target = max_target / difficulty;
        return ArithToUint256(target);
    }

private:
    EquihashBlockHeader m_current_header;
    uint64_t m_current_height{0};
    unsigned int m_equihash_n;
    unsigned int m_equihash_k;
};

/**
 * Horizen (formerly ZenCash) - uses Equihash 200,9 with different params
 */
class HorizenChainHandler : public EquihashChainHandler {
public:
    explicit HorizenChainHandler(const ParentChainConfig& config)
        : EquihashChainHandler(config) {
        SetEquihashParams(200, 9);
    }
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_EQUIHASH_H
