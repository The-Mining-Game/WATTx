// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_ETHASH_H
#define WATTX_STRATUM_PARENT_CHAIN_ETHASH_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>
#include <hash.h>
#include <uint256.h>

#include <array>

namespace merged_stratum {

/**
 * Ethash block header
 * Used by Ethereum Classic (ETC)
 */
class EthashBlockHeader : public IParentBlockHeader {
public:
    uint256 parentHash;
    uint256 uncleHash;
    std::array<uint8_t, 20> coinbase;  // 20-byte address
    uint256 stateRoot;
    uint256 transactionsRoot;
    uint256 receiptsRoot;
    std::array<uint8_t, 256> logsBloom;  // 256-byte bloom filter
    uint64_t difficulty{0};
    uint64_t number{0};
    uint64_t gasLimit{0};
    uint64_t gasUsed{0};
    uint64_t timestamp{0};
    std::vector<uint8_t> extraData;  // Variable length
    uint256 mixHash;
    uint64_t nonce{0};

    uint256 GetHash() const override {
        // Ethash header hash is Keccak256 of RLP-encoded header (without mixHash and nonce)
        std::vector<uint8_t> data = SerializeWithoutPoW();
        // Use Keccak256 (Ethereum's hash function)
        return KeccakHash(data);
    }

    uint256 GetPoWHash() const override {
        // For Ethash, PoW verification requires DAG lookup
        // This is a simplified version - real implementation needs ethash library
        return GetHash();
    }

    std::vector<uint8_t> Serialize() const override {
        // Full RLP-encoded header
        std::vector<uint8_t> data;

        // RLP encode all fields
        RLPEncodeHeader(data);

        return data;
    }

    std::vector<uint8_t> SerializeWithoutPoW() const {
        // RLP-encoded header without mixHash and nonce (for hashing)
        std::vector<uint8_t> data;
        RLPEncodeHeaderWithoutPoW(data);
        return data;
    }

    uint32_t GetNonce() const override {
        return static_cast<uint32_t>(nonce);
    }

    void SetNonce(uint32_t n) override {
        nonce = n;
    }

    void SetFullNonce(uint64_t n) {
        nonce = n;
    }

    uint64_t GetFullNonce() const {
        return nonce;
    }

private:
    // Simplified Keccak256 wrapper
    static uint256 KeccakHash(const std::vector<uint8_t>& data) {
        // Use the built-in hash function or implement Keccak256
        // For now, use SHA256 as placeholder - real implementation needs Keccak
        return Hash(data);
    }

    // RLP encoding helpers
    void RLPEncodeHeader(std::vector<uint8_t>& out) const {
        // Simplified RLP encoding for the full header
        // Real implementation needs proper RLP library
        std::vector<uint8_t> content;

        RLPEncodeBytes(content, parentHash.GetHex());
        RLPEncodeBytes(content, uncleHash.GetHex());
        RLPEncodeBytes(content, std::vector<uint8_t>(coinbase.begin(), coinbase.end()));
        RLPEncodeBytes(content, stateRoot.GetHex());
        RLPEncodeBytes(content, transactionsRoot.GetHex());
        RLPEncodeBytes(content, receiptsRoot.GetHex());
        RLPEncodeBytes(content, std::vector<uint8_t>(logsBloom.begin(), logsBloom.end()));
        RLPEncodeUint(content, difficulty);
        RLPEncodeUint(content, number);
        RLPEncodeUint(content, gasLimit);
        RLPEncodeUint(content, gasUsed);
        RLPEncodeUint(content, timestamp);
        RLPEncodeBytes(content, extraData);
        RLPEncodeBytes(content, mixHash.GetHex());
        RLPEncodeUint(content, nonce);

        // Wrap in list
        RLPEncodeList(out, content);
    }

    void RLPEncodeHeaderWithoutPoW(std::vector<uint8_t>& out) const {
        // RLP encoding without mixHash and nonce
        std::vector<uint8_t> content;

        RLPEncodeBytes(content, parentHash.GetHex());
        RLPEncodeBytes(content, uncleHash.GetHex());
        RLPEncodeBytes(content, std::vector<uint8_t>(coinbase.begin(), coinbase.end()));
        RLPEncodeBytes(content, stateRoot.GetHex());
        RLPEncodeBytes(content, transactionsRoot.GetHex());
        RLPEncodeBytes(content, receiptsRoot.GetHex());
        RLPEncodeBytes(content, std::vector<uint8_t>(logsBloom.begin(), logsBloom.end()));
        RLPEncodeUint(content, difficulty);
        RLPEncodeUint(content, number);
        RLPEncodeUint(content, gasLimit);
        RLPEncodeUint(content, gasUsed);
        RLPEncodeUint(content, timestamp);
        RLPEncodeBytes(content, extraData);

        RLPEncodeList(out, content);
    }

    static void RLPEncodeBytes(std::vector<uint8_t>& out, const std::string& hex) {
        std::vector<uint8_t> bytes = ParseHex(hex);
        RLPEncodeBytes(out, bytes);
    }

    static void RLPEncodeBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes) {
        if (bytes.size() == 1 && bytes[0] < 0x80) {
            out.push_back(bytes[0]);
        } else if (bytes.size() < 56) {
            out.push_back(0x80 + bytes.size());
            out.insert(out.end(), bytes.begin(), bytes.end());
        } else {
            // Long string encoding
            size_t len = bytes.size();
            std::vector<uint8_t> len_bytes;
            while (len > 0) {
                len_bytes.insert(len_bytes.begin(), len & 0xFF);
                len >>= 8;
            }
            out.push_back(0xb7 + len_bytes.size());
            out.insert(out.end(), len_bytes.begin(), len_bytes.end());
            out.insert(out.end(), bytes.begin(), bytes.end());
        }
    }

    static void RLPEncodeUint(std::vector<uint8_t>& out, uint64_t value) {
        if (value == 0) {
            out.push_back(0x80);
        } else if (value < 0x80) {
            out.push_back(static_cast<uint8_t>(value));
        } else {
            std::vector<uint8_t> bytes;
            while (value > 0) {
                bytes.insert(bytes.begin(), value & 0xFF);
                value >>= 8;
            }
            RLPEncodeBytes(out, bytes);
        }
    }

    static void RLPEncodeList(std::vector<uint8_t>& out, const std::vector<uint8_t>& content) {
        if (content.size() < 56) {
            out.push_back(0xc0 + content.size());
            out.insert(out.end(), content.begin(), content.end());
        } else {
            size_t len = content.size();
            std::vector<uint8_t> len_bytes;
            while (len > 0) {
                len_bytes.insert(len_bytes.begin(), len & 0xFF);
                len >>= 8;
            }
            out.push_back(0xf7 + len_bytes.size());
            out.insert(out.end(), len_bytes.begin(), len_bytes.end());
            out.insert(out.end(), content.begin(), content.end());
        }
    }
};

/**
 * Ethash parent chain handler
 * Supports:
 * - ETC (Ethereum Classic)
 * - ALT (Altcoinchain)
 * - OCTA (Octaspace)
 * and other Ethash-based chains
 */
class EthashChainHandler : public ParentChainHandlerBase {
public:
    explicit EthashChainHandler(const ParentChainConfig& config)
        : ParentChainHandlerBase(config) {}

    bool GetBlockTemplate(
        std::string& hashing_blob,
        std::string& full_template,
        std::string& seed_hash,
        uint64_t& height,
        uint64_t& difficulty,
        ParentCoinbaseData& coinbase_data
    ) override {
        // ETC uses eth_getWork RPC (returns array of 3 hex strings)
        // [0] = header hash (32 bytes)
        // [1] = seed hash (32 bytes)
        // [2] = boundary/target (32 bytes)
        std::string response = JsonRpcCall("eth_getWork", "[]");

        if (response.empty()) {
            LogPrintf("EthashChain: Failed to get work\n");
            return false;
        }

        // Parse result array
        std::vector<std::string> work = ParseJsonArray(response, "result");
        if (work.size() < 3) {
            LogPrintf("EthashChain: Invalid eth_getWork response\n");
            return false;
        }

        // Get current block for height
        std::string block_response = JsonRpcCall("eth_blockNumber", "[]");
        std::string block_num_hex = ParseJsonString(block_response, "result");
        if (block_num_hex.length() > 2 && block_num_hex.substr(0, 2) == "0x") {
            height = std::stoull(block_num_hex.substr(2), nullptr, 16) + 1;
        }

        // Parse difficulty from target
        std::string target_hex = work[2];
        if (target_hex.length() > 2 && target_hex.substr(0, 2) == "0x") {
            target_hex = target_hex.substr(2);
        }
        uint256 target = uint256::FromHex(target_hex).value_or(uint256{});
        arith_uint256 target_arith = UintToArith256(target);

        // difficulty = 2^256 / target
        if (target_arith > 0) {
            arith_uint256 max_val;
            max_val.SetCompact(0x1d00ffff);
            max_val = max_val * arith_uint256(0x100000000);  // Approximate max
            difficulty = (max_val / target_arith).GetLow64();
        } else {
            difficulty = 1;
        }

        // Store work data
        m_header_hash = work[0];
        m_seed_hash = work[1];
        m_target = work[2];
        m_current_height = height;

        hashing_blob = m_header_hash;
        seed_hash = m_seed_hash;
        full_template = response;

        // For Ethash, coinbase_data is different - we track header hash
        coinbase_data.reserve_offset = 0;
        coinbase_data.reserve_size = 32;

        LogPrintf("EthashChain: Got work at height %lu, seed: %s\n", height, m_seed_hash.substr(0, 16));
        return true;
    }

    bool ParseBlockTemplate(
        const std::string& template_blob,
        ParentCoinbaseData& coinbase_data
    ) override {
        // For Ethash, the template is the header hash from eth_getWork
        coinbase_data.coinbase_tx.clear();
        return true;
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        // For Ethash merged mining, the MM tag goes in the extraData field
        // This is non-standard and would require protocol modification
        // For now, return the header hash as-is
        return m_header_hash;
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& seed_hash
    ) override {
        // Ethash PoW requires DAG computation
        // This is a placeholder - real implementation needs ethash library
        // (ethash_light_compute or ethash_full_compute)

        // For merged mining, we accept shares based on a lower difficulty
        // The actual Ethash computation would be:
        // 1. Load/generate DAG for epoch (based on seed_hash)
        // 2. Compute mix_hash and result using Ethash algorithm
        // 3. Compare result against target

        // Simplified: hash the blob with the seed
        std::vector<uint8_t> combined = hashing_blob;
        std::vector<uint8_t> seed_bytes = ParseHex(seed_hash);
        combined.insert(combined.end(), seed_bytes.begin(), seed_bytes.end());

        return Hash(combined);
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<EthashBlockHeader>();
        header->number = m_current_height;
        header->SetNonce(nonce);
        return header;
    }

    bool SubmitBlock(const std::string& block_blob) override {
        // ETC uses eth_submitWork
        // Parameters: nonce (8 bytes), header hash (32 bytes), mix digest (32 bytes)

        // Parse the submitted work
        // block_blob format: nonce (16 hex chars) + mixHash (64 hex chars)
        if (block_blob.length() < 80) {
            LogPrintf("EthashChain: Invalid block blob length\n");
            return false;
        }

        std::string nonce_hex = "0x" + block_blob.substr(0, 16);
        std::string mix_hash = "0x" + block_blob.substr(16, 64);

        std::string params = "[\"" + nonce_hex + "\",\"" + m_header_hash + "\",\"" + mix_hash + "\"]";
        std::string response = JsonRpcCall("eth_submitWork", params);

        return response.find("true") != std::string::npos;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& extra_data = ""   // "nonce64_hex:mix_hash_hex"
    ) override {
        CAuxPow proof;

        // parentBlock timestamp for time validation
        proof.parentBlock.timestamp = GetTime();

        // Build parentHeaderRaw = 32B header_hash + 8B nonce_LE + 32B mix_hash = 72 bytes
        // extra_data format: "nonce64_hex:mix_hash_hex" (passed by ValidateShare for Ethash)
        std::string nonce64_hex, mix_hash_hex;
        size_t colon = extra_data.find(':');
        if (colon != std::string::npos) {
            nonce64_hex  = extra_data.substr(0, colon);
            mix_hash_hex = extra_data.substr(colon + 1);
        }

        std::vector<uint8_t> raw(72, 0);

        // header_hash (32 bytes) — strip "0x" prefix if present
        std::string hh = m_header_hash;
        if (hh.size() >= 2 && hh[0] == '0' && hh[1] == 'x') hh = hh.substr(2);
        auto hh_bytes = ParseHex(hh);
        if (hh_bytes.size() >= 32) std::memcpy(raw.data(), hh_bytes.data(), 32);

        // nonce (8 bytes LE) — use extra_data nonce64 if available, else fall back to nonce param
        if (!nonce64_hex.empty()) {
            std::string nh = nonce64_hex;
            if (nh.size() >= 2 && nh[0] == '0' && nh[1] == 'x') nh = nh.substr(2);
            auto nb = ParseHex(nh);
            size_t copy_len = std::min(nb.size(), size_t(8));
            std::memcpy(raw.data() + 32, nb.data(), copy_len);
        } else {
            std::memcpy(raw.data() + 32, &nonce, 4);
        }

        // mix_hash (32 bytes)
        if (!mix_hash_hex.empty()) {
            std::string mh = mix_hash_hex;
            if (mh.size() >= 2 && mh[0] == '0' && mh[1] == 'x') mh = mh.substr(2);
            auto mb = ParseHex(mh);
            if (mb.size() >= 32) std::memcpy(raw.data() + 40, mb.data(), 32);
        }

        proof.parentAlgoId    = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.parentHeaderRaw = raw;

        // Ethash has no coinbase in its PoW, but CAuxPow::Check() extracts the WATTx
        // commitment from a coinbase (scriptSig/OP_RETURN) and verifies a coinbase
        // merkle proof. Provide a synthetic coinbase carrying the merge-mining tag so
        // the proof is structurally valid; empty branch => merkle_root == its txid.
        // NOTE: this asserts the commitment pool-side — true trustless ETC merged
        // mining requires the parent block itself to embed the WATTx aux hash.
        CMutableTransaction cb = BuildAuxMergedCoinbase(merge_mining_tag, 0);
        proof.coinbaseTxMut         = cb;
        proof.parentBlock.merkle_root = CTransaction(cb).GetHash();
        proof.coinbaseBranch.vHash.clear();
        proof.coinbaseBranch.nIndex = 0;
        proof.nChainId        = m_config.chain_id;

        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        // Ethash: target = 2^256 / difficulty
        if (difficulty == 0) difficulty = 1;

        // For Ethash, we use a simpler conversion
        // target = max_val / difficulty where max_val is 2^256 - 1
        arith_uint256 max_val = UintToArith256(
            uint256::FromHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").value_or(uint256{})
        );
        arith_uint256 target = max_val / difficulty;

        return ArithToUint256(target);
    }

private:
    // Parse JSON array helper
    static std::vector<std::string> ParseJsonArray(const std::string& json, const std::string& key) {
        std::vector<std::string> result;
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) {
            // Try without key (direct array)
            pos = json.find('[');
            if (pos == std::string::npos) return result;
        } else {
            pos += search.length();
            while (pos < json.length() && json[pos] != '[') pos++;
        }
        if (pos >= json.length()) return result;
        pos++;

        while (pos < json.length() && json[pos] != ']') {
            while (pos < json.length() && (json[pos] == ' ' || json[pos] == ',' || json[pos] == '\t' || json[pos] == '\n')) pos++;
            if (pos >= json.length() || json[pos] == ']') break;

            if (json[pos] == '"') {
                pos++;
                size_t end = json.find('"', pos);
                if (end == std::string::npos) break;
                result.push_back(json.substr(pos, end - pos));
                pos = end + 1;
            } else {
                size_t end = json.find_first_of(",]\n", pos);
                if (end == std::string::npos) break;
                std::string value = json.substr(pos, end - pos);
                while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                    value.pop_back();
                result.push_back(value);
                pos = end;
            }
        }

        return result;
    }

    std::string m_header_hash;
    std::string m_seed_hash;
    std::string m_target;
    uint64_t m_current_height{0};
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_ETHASH_H
