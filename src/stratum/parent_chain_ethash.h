// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_ETHASH_H
#define WATTX_STRATUM_PARENT_CHAIN_ETHASH_H

#include <stratum/parent_chain_base.h>
#include <auxpow/ethash_seal.h>
#include <arith_uint256.h>
#include <hash.h>
#include <uint256.h>

#include <algorithm>
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

        // Carry geth's EXACT boundary as the parent target (big-endian numeric,
        // via FromHex). Deriving it from the integer difficulty above is only
        // approximate and would make meets_parent fire on the wrong solutions;
        // an exact target is what makes true dual-earning (one solution clears
        // geth AND WATTx) correct.
        coinbase_data.parent_target = target;

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

    // Serialize one V2 field: [u16 LE length][bytes].
    static void PutField(std::vector<uint8_t>& out, const std::vector<uint8_t>& f) {
        out.push_back(static_cast<uint8_t>(f.size() & 0xff));
        out.push_back(static_cast<uint8_t>((f.size() >> 8) & 0xff));
        out.insert(out.end(), f.begin(), f.end());
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& extra_data = ""   // "nonce64_hex:mix_hash_hex"
    ) override {
        CAuxPow proof;
        proof.parentBlock.timestamp = GetTime();
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.nChainId     = m_config.chain_id;

        // The submitted solution: nonce (8B) + mix (32B), from ValidateShare.
        std::string nonce64_hex, mix_hash_hex;
        size_t colon = extra_data.find(':');
        if (colon != std::string::npos) {
            nonce64_hex  = extra_data.substr(0, colon);
            mix_hash_hex = extra_data.substr(colon + 1);
        }
        auto strip0x = [](std::string s) {
            if (s.size() >= 2 && s[0] == '0' && s[1] == 'x') return s.substr(2);
            return s;
        };
        std::vector<uint8_t> nonce_bytes(8, 0), mix_bytes(32, 0);
        if (!nonce64_hex.empty()) {
            auto nb = ParseHex(strip0x(nonce64_hex));
            // geth block nonce is big-endian; ethash hashes it little-endian, and
            // the WATTx gate/consensus consume the nonce LE (matches eth_dualwatch).
            std::reverse(nb.begin(), nb.end());
            for (size_t i = 0; i < nb.size() && i < 8; ++i) nonce_bytes[i] = nb[i];
        }
        if (!mix_hash_hex.empty()) {
            auto mb = ParseHex(strip0x(mix_hash_hex));
            if (mb.size() >= 32) std::memcpy(mix_bytes.data(), mb.data(), 32);
        }

        // TRUSTLESS full-header format (ParseEthashV2 in auxpow.cpp):
        //   [0x02][hasBaseFee] {14|13 × [u16 LE len][bytes]} [8B nonce][32B mix]
        // Built from the FULL geth header snapshot (coinbase_data.eth_*), so
        // consensus recomputes the SAME seal hash the miner solved and verifies
        // that header's extraData commits to this WATTx block. No synthetic
        // coinbase — the ALT block itself carries the commitment.
        if (coinbase_data.eth_header_valid) {
            std::vector<uint8_t> raw;
            raw.push_back(0x02);
            raw.push_back(coinbase_data.eth_hasBaseFee ? 1 : 0);
            PutField(raw, coinbase_data.eth_parentHash);
            PutField(raw, coinbase_data.eth_uncleHash);
            PutField(raw, coinbase_data.eth_coinbase);
            PutField(raw, coinbase_data.eth_root);
            PutField(raw, coinbase_data.eth_txHash);
            PutField(raw, coinbase_data.eth_receiptHash);
            PutField(raw, coinbase_data.eth_bloom);
            PutField(raw, coinbase_data.eth_difficulty);
            PutField(raw, coinbase_data.eth_number);
            PutField(raw, coinbase_data.eth_gasLimit);
            PutField(raw, coinbase_data.eth_gasUsed);
            PutField(raw, coinbase_data.eth_time);
            PutField(raw, coinbase_data.eth_extra);
            if (coinbase_data.eth_hasBaseFee) PutField(raw, coinbase_data.eth_baseFee);
            raw.insert(raw.end(), nonce_bytes.begin(), nonce_bytes.end());
            raw.insert(raw.end(), mix_bytes.begin(), mix_bytes.end());
            proof.parentHeaderRaw = raw;
        } else {
            // No full header snapshot → cannot build a trustless proof. Leave
            // parentHeaderRaw empty; CAuxPow::Check rejects it (fail closed).
            LogPrintf("EthashChain: CreateAuxPow without full-header snapshot — "
                      "trustless proof unavailable\n");
        }
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

    // Fetch the FULL sealing header from geth (eth_getSealingHeader — the header
    // whose seal hash eth_getWork returns; unlike "pending" it has miner/stateRoot
    // populated) and fill coinbase_data.eth_* so CreateAuxPow can build the
    // trustless V2 proof. Returns false if unavailable/malformed (fail closed).
    bool FetchSealingHeader(ParentCoinbaseData& cb) {
        std::string resp = JsonRpcCall("eth_getSealingHeader", "[]");
        if (resp.empty() || resp.find("\"result\"") == std::string::npos) return false;
        auto dec = [&](const char* key) -> std::vector<uint8_t> {
            std::string v = ParseJsonString(resp, key);
            if (v.size() >= 2 && v[0] == '0' && v[1] == 'x') v = v.substr(2);
            if (v.size() % 2) v = "0" + v;  // pad odd-length quantities
            return ParseHex(v);
        };
        cb.eth_parentHash  = dec("parentHash");
        cb.eth_uncleHash   = dec("sha3Uncles");
        cb.eth_coinbase    = dec("miner");
        cb.eth_root        = dec("stateRoot");
        cb.eth_txHash      = dec("transactionsRoot");
        cb.eth_receiptHash = dec("receiptsRoot");
        cb.eth_bloom       = dec("logsBloom");
        cb.eth_difficulty  = dec("difficulty");
        cb.eth_number      = dec("number");
        cb.eth_gasLimit    = dec("gasLimit");
        cb.eth_gasUsed     = dec("gasUsed");
        cb.eth_time        = dec("timestamp");
        cb.eth_extra       = dec("extraData");
        cb.eth_baseFee     = dec("baseFeePerGas");
        cb.eth_hasBaseFee  = !cb.eth_baseFee.empty();
        if (cb.eth_parentHash.size() != 32 || cb.eth_uncleHash.size() != 32 ||
            cb.eth_coinbase.size() != 20 || cb.eth_root.size() != 32 ||
            cb.eth_txHash.size() != 32 || cb.eth_receiptHash.size() != 32 ||
            cb.eth_bloom.size() != 256) {
            cb.eth_header_valid = false;
            return false;
        }
        cb.eth_header_valid = true;

        // Compute the seal hash of THIS exact header locally so the miner grinds
        // the same header the AuxPoW proof is built from (eth_getWork could race
        // a geth rebuild). Consensus recomputes it identically (ethash_seal.h).
        ethseal::EthHeaderFields h;
        h.parentHash = cb.eth_parentHash; h.uncleHash = cb.eth_uncleHash;
        h.coinbase = cb.eth_coinbase;     h.root = cb.eth_root;
        h.txHash = cb.eth_txHash;         h.receiptHash = cb.eth_receiptHash;
        h.bloom = cb.eth_bloom;           h.extra = cb.eth_extra;
        h.difficulty = cb.eth_difficulty; h.number = cb.eth_number;
        h.gasLimit = cb.eth_gasLimit;     h.gasUsed = cb.eth_gasUsed;
        h.time = cb.eth_time;             h.baseFee = cb.eth_baseFee;
        h.hasBaseFee = cb.eth_hasBaseFee;
        auto seal = ethseal::SealHash(h);
        static const char* hexd = "0123456789abcdef";
        std::string sh = "0x";
        for (uint8_t b : seal) { sh += hexd[b >> 4]; sh += hexd[b & 0xf]; }
        m_header_hash = sh;
        return true;
    }

    // Trustless commit-then-mine: tell geth to embed THIS job's aux commitment
    // (aux_root, from the merge-mining tag) in the block it seals, then snapshot
    // the committed sealing header. The commitment lands in the next template
    // geth builds; a background committed-header cache (TODO) will remove the
    // per-job latency. Called by CreateJob before BuildHashingBlob.
    bool PrepareTaggedTemplate(
        ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        if (merge_mining_tag.size() >= 34) {
            // tag = [0x03][depth][32B aux_root]
            std::vector<uint8_t> aux_root(merge_mining_tag.begin() + 2,
                                          merge_mining_tag.begin() + 34);
            static const char* hexd = "0123456789abcdef";
            std::string root_hex = "0x";
            for (uint8_t b : aux_root) { root_hex += hexd[b >> 4]; root_hex += hexd[b & 0xf]; }
            JsonRpcCall("mm_setCommitment", "[\"" + root_hex + "\"]");
        }
        // Snapshot the current sealing header (may still carry the previous
        // commitment until geth rebuilds; CreateAuxPow/Check fail-close if the
        // extraData doesn't match this job's aux block, so a not-yet-committed
        // header simply won't land a WATTx block — no unbound proof is produced).
        FetchSealingHeader(coinbase_data);
        return true;
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
