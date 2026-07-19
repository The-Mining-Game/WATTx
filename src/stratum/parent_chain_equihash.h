// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_EQUIHASH_H
#define WATTX_STRATUM_PARENT_CHAIN_EQUIHASH_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>
#include <crypto/equihash/equihash_canon.h>  // canonical Zcash/BitcoinZ validator
#include <streams.h>  // DataStream (coinbase serialization)

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

        // Snapshot the header into coinbase_data so BuildHashingBlob and
        // CreateAuxPow rebuild the SAME header even after the 5s poller has
        // refreshed m_current_header (same pattern as the Bitcoin handler).
        coinbase_data.parent_version  = m_current_header.nVersion;
        coinbase_data.parent_prevhash = m_current_header.hashPrevBlock;
        coinbase_data.parent_time     = m_current_header.nTime;
        coinbase_data.parent_bits     = m_current_header.nBits;
        coinbase_data.parent_height   = height;
        coinbase_data.parent_reserved = m_current_header.hashReserved;
        coinbase_data.header_snapshot = true;

        // The parent's exact block target (deriving from integer difficulty
        // floors at diff-1 and makes regtest targets unreachable).
        std::string target_str = ParseJsonString(response, "target");
        if (!target_str.empty()) {
            coinbase_data.parent_target = uint256::FromHex(target_str).value_or(uint256{});
        }

        // REAL parent coinbase: zcashd-family GBT provides the fully-built
        // coinbase (with any founders-reward outputs) as coinbasetxn.data.
        // Append a 34B merge-mining-tag reserve + 8B extranonce to its
        // scriptSig so one share can land the BitcoinZ block AND the WATTx
        // block (dual-earning). On any parse surprise fall back to the
        // synthetic coinbase (WTX-only, parent submits rejected).
        ParseCoinbaseTxn(response, coinbase_data);

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

    // Extract coinbasetxn.data from the GBT response and patch its scriptSig
    // with tag + extranonce space. The naive substring JSON parser would grab
    // the first "data" key — which belongs to a mempool tx when transactions[]
    // is non-empty — so search only after the "coinbasetxn" key.
    void ParseCoinbaseTxn(const std::string& response, ParentCoinbaseData& cd) {
        size_t cbpos = response.find("\"coinbasetxn\"");
        if (cbpos == std::string::npos) return;
        size_t dpos = response.find("\"data\"", cbpos);
        if (dpos == std::string::npos) return;
        size_t vstart = response.find('"', response.find(':', dpos));
        if (vstart == std::string::npos) return;
        size_t vend = response.find('"', vstart + 1);
        if (vend == std::string::npos) return;
        std::vector<uint8_t> tx = ParseHex(response.substr(vstart + 1, vend - vstart - 1));
        if (tx.size() < 4 + 1 + 36 + 1 + 4) return;

        // vin count offset: 4 (v1/v2) or 8 (overwintered v3/v4 add nVersionGroupId)
        uint32_t version = tx[0] | (tx[1] << 8) | (tx[2] << 16) |
                           (uint32_t(tx[3]) << 24);
        size_t pos = (version & 0x80000000) ? 8 : 4;
        if (tx.size() < pos + 1 + 36 + 1 || tx[pos] != 0x01) return;  // 1 input
        pos += 1 + 36;                        // vin count + prevout
        uint8_t script_len = tx[pos];
        if (script_len >= 0xFD) return;       // 1-byte varint assumed
        static constexpr size_t INSERT = 34 + AUX_COINBASE_EXTRANONCE_SIZE;
        if (script_len + INSERT > 100) {      // consensus coinbase scriptSig cap
            LogPrintf("EquihashChain: coinbase scriptSig too long to patch (%d)\n", script_len);
            return;
        }
        size_t script_end = pos + 1 + script_len;
        if (tx.size() < script_end + 4) return;

        tx[pos] = script_len + INSERT;
        tx.insert(tx.begin() + script_end, INSERT, 0x00);

        cd.coinbase_tx       = std::move(tx);
        cd.reserve_offset    = script_end;         // 34B tag lands here
        cd.reserve_size      = 34;
        cd.extranonce_offset = script_end + 34;
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

    // Rebuild the 140-byte header from the job's frozen snapshot — never from
    // m_current_header, which the 5s poller mutates while shares are in flight.
    EquihashBlockHeader HeaderFromSnapshot(const ParentCoinbaseData& cd) const {
        EquihashBlockHeader h;
        h.nVersion      = cd.parent_version;
        h.hashPrevBlock = cd.parent_prevhash;
        h.hashReserved  = cd.parent_reserved;
        h.nTime         = cd.parent_time;
        h.nBits         = cd.parent_bits;
        return h;
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        // Commit the mined 140-byte header to the synthetic coinbase that carries
        // the WATTx merge-mining tag; CreateAuxPow rebuilds the identical coinbase
        // so the proof reproduces this exact merkle root (single-tx tree).
        EquihashBlockHeader header = coinbase_data.header_snapshot
            ? HeaderFromSnapshot(coinbase_data) : m_current_header;
        header.hashMerkleRoot = AuxCoinbaseMerkleRoot(coinbase_data, merge_mining_tag);
        return HexStr(header.GetEquihashInput());
    }

    // Serialized coinbase the mined header commits to: the real parent coinbase
    // (tag injected at reserve_offset) when the template provided one, else the
    // deterministic synthetic aux coinbase.
    std::vector<uint8_t> AuxCoinbaseBytes(
        const ParentCoinbaseData& cd,
        const std::vector<uint8_t>& merge_mining_tag
    ) const {
        if (!cd.coinbase_tx.empty()) {
            std::vector<uint8_t> cb = cd.coinbase_tx;
            if (cd.reserve_offset > 0 &&
                cd.reserve_offset + merge_mining_tag.size() <= cb.size()) {
                std::memcpy(&cb[cd.reserve_offset],
                            merge_mining_tag.data(), merge_mining_tag.size());
            }
            return cb;
        }
        CMutableTransaction cb = BuildAuxMergedCoinbase(
            merge_mining_tag,
            cd.header_snapshot ? cd.parent_height : m_current_height);
        DataStream ss;
        ss << TX_NO_WITNESS(CTransaction(cb));
        std::vector<uint8_t> out(ParseHex(HexStr(ss)));
        return out;
    }

    uint256 AuxCoinbaseMerkleRoot(
        const ParentCoinbaseData& cd,
        const std::vector<uint8_t>& merge_mining_tag
    ) const {
        // Single-tx block: merkle root == txid == SHA256d of the serialization
        // (identical rule for zcash-family and bitcoin).
        return Hash(AuxCoinbaseBytes(cd, merge_mining_tag));
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
        // Canonical Zcash/BitcoinZ validator (matches the parent daemon), keyed
        // by this handler's (n,k). header_data is the 140-byte header (through
        // the 32-byte nonce); solution is the raw compressed solution.
        return equihash_canon::Verify(m_equihash_n, m_equihash_k,
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
        // submitblock: null result = accepted, string result = reject reason.
        // An RPC ERROR (e.g. -22 Block decode failed) ALSO carries result:null
        // with a populated error object — require error:null too, or rejected
        // submissions get logged (and counted) as parent blocks.
        bool ok = response.find("\"result\":null") != std::string::npos &&
                  response.find("\"error\":null") != std::string::npos;
        if (!ok) {
            LogPrintf("EquihashChain: submitblock rejected: %s\n",
                      response.substr(0, 300));
        }
        return ok;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& extra_data = ""
    ) override {
        CAuxPow proof;

        // extra_data = "nonce_hex:solution_hex" — the full 32-byte nonce and the
        // raw Equihash solution the miner submitted. Consensus (CAuxPow::Check)
        // canonically verifies the solution, so without it the proof cannot pass.
        uint256 nonce256;
        std::vector<uint8_t> solution;
        if (size_t colon = extra_data.find(':'); colon != std::string::npos) {
            std::vector<uint8_t> nb = ParseHex(extra_data.substr(0, colon));
            std::memcpy(nonce256.data(), nb.data(), std::min<size_t>(nb.size(), 32));
            solution = ParseHex(extra_data.substr(colon + 1));
        }

        // Rebuild the SAME coinbase the miner committed to, so its txid is the
        // single-tx merkle root of both the mined header and the proof.
        std::vector<uint8_t> cb_bytes = AuxCoinbaseBytes(coinbase_data, merge_mining_tag);
        uint256 merkle_root = Hash(cb_bytes);

        EquihashBlockHeader parent_header = coinbase_data.header_snapshot
            ? HeaderFromSnapshot(coinbase_data) : m_current_header;
        parent_header.hashMerkleRoot = merkle_root;
        parent_header.SetNonce256(nonce256);
        parent_header.nSolution = solution;

        // parentBlock: merkle_root for Check(), timestamp for time validation
        proof.parentBlock.timestamp   = parent_header.nTime;
        proof.parentBlock.merkle_root = merkle_root;

        // parentHeaderRaw layout (must match ParseEquihashRaw in auxpow.cpp):
        // [n LE32][k LE32][140B header][CompactSize(sol)+solution][coinbase raw]
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::EQUIHASH);
        std::vector<uint8_t> raw;
        raw.reserve(8 + 140 + 3 + solution.size() + cb_bytes.size());
        for (int i = 0; i < 4; i++) raw.push_back((m_equihash_n >> (8 * i)) & 0xFF);
        for (int i = 0; i < 4; i++) raw.push_back((m_equihash_k >> (8 * i)) & 0xFF);
        std::vector<uint8_t> full = parent_header.Serialize();  // header + cs + sol
        raw.insert(raw.end(), full.begin(), full.end());
        raw.insert(raw.end(), cb_bytes.begin(), cb_bytes.end());
        proof.parentHeaderRaw = std::move(raw);

        proof.coinbaseTxMut = BuildAuxMergedCoinbase(
            merge_mining_tag,
            coinbase_data.header_snapshot ? coinbase_data.parent_height : m_current_height);
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

/**
 * BitcoinZ - uses Equihash 144,5 ("zhash", GPU-friendly) on mainnet/testnet.
 * (Regtest is 48,5 — set via SetEquihashParams(48,5) for regtest testing.)
 */
class BitcoinZChainHandler : public EquihashChainHandler {
public:
    explicit BitcoinZChainHandler(const ParentChainConfig& config)
        : EquihashChainHandler(config) {
        SetEquihashParams(144, 5);
    }
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_EQUIHASH_H
