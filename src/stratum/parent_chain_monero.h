// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_MONERO_H
#define WATTX_STRATUM_PARENT_CHAIN_MONERO_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>
#include <auxpow/auxpow.h>  // MoneroTxHash / MoneroTreeFold (CryptoNote hashing)
#include <node/randomx_miner.h>

namespace merged_stratum {

/**
 * Monero block header for RandomX PoW
 */
class MoneroBlockHeader : public IParentBlockHeader {
public:
    uint8_t major_version{0};
    uint8_t minor_version{0};
    uint64_t timestamp{0};
    uint256 prev_id;
    uint32_t nonce{0};
    uint256 merkle_root;
    uint64_t num_txs{1};  // total txs incl. miner tx — blob tail varint

    uint256 GetHash() const override {
        // Monero block ID (blob hash)
        std::vector<uint8_t> data = Serialize();
        return Hash(data);
    }

    uint256 GetPoWHash() const override {
        // RandomX hash of the hashing blob
        std::vector<uint8_t> blob = BuildHashingBlob();

        uint256 hash;
        auto& miner = node::GetRandomXMiner();
        if (miner.IsInitialized()) {
            miner.CalculateHash(blob.data(), blob.size(), hash.data());
        } else {
            hash = Hash(blob);
            LogPrintf("MoneroChain: RandomX not initialized, using SHA256d fallback\n");
        }

        return hash;
    }

    std::vector<uint8_t> BuildHashingBlob() const {
        std::vector<uint8_t> blob;
        blob.reserve(76);

        // Major version
        blob.push_back(major_version);

        // Minor version
        blob.push_back(minor_version);

        // Timestamp as varint
        uint64_t ts = timestamp;
        while (ts >= 0x80) {
            blob.push_back((ts & 0x7F) | 0x80);
            ts >>= 7;
        }
        blob.push_back(static_cast<uint8_t>(ts));

        // Previous block hash
        blob.insert(blob.end(), prev_id.begin(), prev_id.end());

        // Nonce (4 bytes, little-endian)
        blob.push_back((nonce >> 0) & 0xFF);
        blob.push_back((nonce >> 8) & 0xFF);
        blob.push_back((nonce >> 16) & 0xFF);
        blob.push_back((nonce >> 24) & 0xFF);

        // Tree root (merkle_root)
        blob.insert(blob.end(), merkle_root.begin(), merkle_root.end());

        // Total tx count (incl. miner tx) as varint — matches monerod's own
        // get_block_hashing_blob, so a winning nonce is submittable for real.
        uint64_t n = num_txs;
        while (n >= 0x80) {
            blob.push_back((n & 0x7F) | 0x80);
            n >>= 7;
        }
        blob.push_back(static_cast<uint8_t>(n));

        return blob;
    }

    std::vector<uint8_t> Serialize() const override {
        return BuildHashingBlob();
    }

    uint32_t GetNonce() const override { return nonce; }
    void SetNonce(uint32_t n) override { nonce = n; }
};

/**
 * Monero/RandomX parent chain handler
 */
class MoneroChainHandler : public ParentChainHandlerBase {
public:
    explicit MoneroChainHandler(const ParentChainConfig& config)
        : ParentChainHandlerBase(config) {}

    bool GetBlockTemplate(
        std::string& hashing_blob,
        std::string& full_template,
        std::string& seed_hash,
        uint64_t& height,
        uint64_t& difficulty,
        ParentCoinbaseData& coinbase_data
    ) override {
        // Reserve 194 bytes for merge mining tag + EVM anchor
        std::ostringstream params;
        params << "{\"wallet_address\":\"" << m_config.wallet_address << "\",\"reserve_size\":194}";

        std::string response = HttpPost("/json_rpc",
            "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_template\",\"params\":" + params.str() + "}");

        if (response.empty()) {
            LogPrintf("MoneroChain: Failed to get block template\n");
            return false;
        }

        // Parse response
        hashing_blob = ParseJsonString(response, "blockhashing_blob");
        full_template = ParseJsonString(response, "blocktemplate_blob");
        seed_hash = ParseJsonString(response, "seed_hash");

        std::string height_str = ParseJsonString(response, "height");
        std::string diff_str = ParseJsonString(response, "difficulty");
        std::string reserve_offset_str = ParseJsonString(response, "reserved_offset");

        if (full_template.empty()) {
            LogPrintf("MoneroChain: Invalid block template response\n");
            return false;
        }

        height = height_str.empty() ? 0 : std::stoull(height_str);
        difficulty = diff_str.empty() ? 0 : std::stoull(diff_str);
        m_current_height = height;
        m_seed_hash = seed_hash;

        // Parse the full block template
        if (!ParseBlockTemplate(full_template, coinbase_data)) {
            LogPrintf("MoneroChain: Failed to parse block template\n");
            return false;
        }

        coinbase_data.reserve_offset = reserve_offset_str.empty() ? 0 : std::stoull(reserve_offset_str);
        coinbase_data.reserve_size = 194;

        // Map monerod's reserved_offset (absolute, into blocktemplate_blob) to a
        // coinbase-relative offset so the tag lands EXACTLY in the reserved
        // tx_extra space — both in the coinbase we hash and in the template blob
        // we submit. Header prefix = major(1) + minor(1) + varint(ts) + prev(32) + nonce(4).
        {
            size_t ts_len = 1;
            for (uint64_t t = m_current_header.timestamp; t >= 0x80; t >>= 7) ts_len++;
            size_t coinbase_start = 1 + 1 + ts_len + 32 + 4;
            if (coinbase_data.reserve_offset > coinbase_start) {
                coinbase_data.extranonce_offset = coinbase_data.reserve_offset - coinbase_start;
            }
        }

        // Freeze the monero header + seed into the job so BuildHashingBlob (mined
        // blob) and CreateAuxPow (proof) agree despite per-poll template churn.
        coinbase_data.mono_major     = m_current_header.major_version;
        coinbase_data.mono_minor     = m_current_header.minor_version;
        coinbase_data.mono_timestamp = m_current_header.timestamp;
        coinbase_data.mono_prev_id   = m_current_header.prev_id;
        {
            std::vector<uint8_t> sb = ParseHex(seed_hash);
            coinbase_data.mono_seed.SetNull();
            if (sb.size() == 32) std::memcpy(coinbase_data.mono_seed.data(), sb.data(), 32);
        }

        LogPrintf("MoneroChain: Got template at height %lu, difficulty %lu\n", height, difficulty);
        return true;
    }

    bool ParseBlockTemplate(
        const std::string& template_blob,
        ParentCoinbaseData& coinbase_data
    ) override {
        std::vector<uint8_t> blob = ParseHex(template_blob);
        if (blob.size() < 100) return false;

        size_t pos = 0;
        uint64_t temp;

        // Parse block header
        pos += ReadVarint(blob, pos, temp);
        m_current_header.major_version = static_cast<uint8_t>(temp);

        pos += ReadVarint(blob, pos, temp);
        m_current_header.minor_version = static_cast<uint8_t>(temp);

        pos += ReadVarint(blob, pos, m_current_header.timestamp);

        if (pos + 32 > blob.size()) return false;
        std::memcpy(m_current_header.prev_id.data(), &blob[pos], 32);
        pos += 32;

        if (pos + 4 > blob.size()) return false;
        m_current_header.nonce = blob[pos] | (blob[pos+1] << 8) | (blob[pos+2] << 16) | (blob[pos+3] << 24);
        pos += 4;

        // Record coinbase start
        size_t coinbase_start = pos;

        // Parse coinbase transaction (simplified)
        pos += ReadVarint(blob, pos, temp);  // version
        pos += ReadVarint(blob, pos, temp);  // unlock_time

        uint64_t vin_count;
        pos += ReadVarint(blob, pos, vin_count);

        for (uint64_t i = 0; i < vin_count && pos < blob.size(); i++) {
            uint8_t input_type = blob[pos++];
            if (input_type == 0xff) {
                pos += ReadVarint(blob, pos, temp);  // height
            }
        }

        uint64_t vout_count;
        pos += ReadVarint(blob, pos, vout_count);

        for (uint64_t i = 0; i < vout_count && pos < blob.size(); i++) {
            pos += ReadVarint(blob, pos, temp);  // amount
            if (pos < blob.size()) {
                uint8_t out_type = blob[pos++];
                if (out_type == 2) pos += 32;
                else if (out_type == 3) pos += 33;
                else pos += 32;
            }
        }

        // Extra field
        uint64_t extra_len;
        pos += ReadVarint(blob, pos, extra_len);
        coinbase_data.reserve_offset = pos;
        coinbase_data.reserve_size = extra_len;
        pos += extra_len;

        size_t coinbase_end = pos;
        coinbase_data.coinbase_tx.assign(blob.begin() + coinbase_start, blob.begin() + coinbase_end);

        // Skip the rct base byte of the v2 miner tx (RCTTypeNull) — the tx PREFIX
        // ends at extra; the tx-hash list follows the rct byte.
        if (!coinbase_data.coinbase_tx.empty() && coinbase_data.coinbase_tx[0] == 0x02 &&
            pos < blob.size() && blob[pos] == 0x00) {
            pos++;
        }

        // Parse transaction hashes for merkle tree — CryptoNote hashing (keccak),
        // NOT SHA256d, so the tree root matches what monerod itself computes.
        uint64_t tx_hash_count;
        pos += ReadVarint(blob, pos, tx_hash_count);
        coinbase_data.mono_tx_count = 1 + tx_hash_count;

        std::vector<uint256> tx_hashes;
        tx_hashes.push_back(auxpow::MoneroTxHash(coinbase_data.coinbase_tx));

        for (uint64_t i = 0; i < tx_hash_count && pos + 32 <= blob.size(); i++) {
            uint256 tx_hash;
            std::memcpy(tx_hash.data(), &blob[pos], 32);
            tx_hashes.push_back(tx_hash);
            pos += 32;
        }

        coinbase_data.coinbase_index = 0;
        coinbase_data.merkle_branch = BuildMerkleBranch(tx_hashes, 0);
        coinbase_data.merkle_root = CalculateMerkleRoot(tx_hashes);

        m_current_header.merkle_root = coinbase_data.merkle_root;

        return true;
    }

    // Inject the merge-mining tag into the monero coinbase tx_extra reserved area
    // and fold the tree root. Deterministic from (coinbase_data, tag) so the mined
    // blob and the AuxPoW proof commit to the identical coinbase + root. The tree
    // hash uses SHA256d (Bitcoin Hash) — internally consistent pool<->validator;
    // NOTE: a Keccak tree hash would additionally make the block valid to monerod
    // for true dual submission (see project notes). Returns the modified coinbase
    // bytes and the resulting root.
    void InjectTagComputeRoot(const ParentCoinbaseData& coinbase_data,
                              const std::vector<uint8_t>& merge_mining_tag,
                              std::vector<uint8_t>& out_coinbase,
                              uint256& out_root) const
    {
        out_coinbase = coinbase_data.coinbase_tx;

        // Preferred: inject at monerod's reserved tx_extra space, mapped to a
        // coinbase-relative offset in GetBlockTemplate. This is exact — the legacy
        // scan below hunts for the first 0x00 in extra, which can false-match a
        // zero byte inside the tx pubkey.
        if (coinbase_data.extranonce_offset > 0 &&
            coinbase_data.extranonce_offset + merge_mining_tag.size() <= out_coinbase.size()) {
            std::memcpy(&out_coinbase[coinbase_data.extranonce_offset],
                        merge_mining_tag.data(), merge_mining_tag.size());
        } else if (coinbase_data.reserve_offset > 0 &&
            coinbase_data.reserve_offset + merge_mining_tag.size() <= out_coinbase.size()) {
            size_t inject_pos = 0;
            size_t pos = 0;
            uint64_t temp;
            pos += ReadVarint(out_coinbase, pos, temp);  // version
            pos += ReadVarint(out_coinbase, pos, temp);  // unlock_time

            uint64_t vin_count;
            pos += ReadVarint(out_coinbase, pos, vin_count);
            for (uint64_t i = 0; i < vin_count && pos < out_coinbase.size(); i++) {
                uint8_t input_type = out_coinbase[pos++];
                if (input_type == 0xff) pos += ReadVarint(out_coinbase, pos, temp);
            }

            uint64_t vout_count;
            pos += ReadVarint(out_coinbase, pos, vout_count);
            for (uint64_t i = 0; i < vout_count && pos < out_coinbase.size(); i++) {
                pos += ReadVarint(out_coinbase, pos, temp);
                if (pos < out_coinbase.size()) {
                    uint8_t out_type = out_coinbase[pos++];
                    if (out_type == 3) pos += 33; else pos += 32;
                }
            }

            uint64_t extra_len;
            pos += ReadVarint(out_coinbase, pos, extra_len);
            size_t extra_start = pos;
            for (size_t i = extra_start; i < extra_start + extra_len && i < out_coinbase.size(); i++) {
                if (out_coinbase[i] == 0) { inject_pos = i; break; }
            }
            if (inject_pos > 0 && inject_pos + merge_mining_tag.size() <= out_coinbase.size()) {
                std::memcpy(&out_coinbase[inject_pos], merge_mining_tag.data(), merge_mining_tag.size());
            }
        }

        // CryptoNote hashing: keccak tx hash folded up a keccak tree — the SAME
        // root monerod computes, so the mined block is valid for real submission.
        uint256 leaf = auxpow::MoneroTxHash(out_coinbase);
        out_root = auxpow::MoneroTreeFold(leaf, coinbase_data.merkle_branch, 0);
    }

    // Rebuild the monero header from the frozen per-job snapshot (immune to the
    // handler's live m_current_header being churned by the poller).
    MoneroBlockHeader SnapshotHeader(const ParentCoinbaseData& cd) const {
        MoneroBlockHeader h;
        h.major_version = cd.mono_major;
        h.minor_version = cd.mono_minor;
        h.timestamp     = cd.mono_timestamp;
        h.prev_id       = cd.mono_prev_id;
        h.nonce         = 0;
        h.num_txs       = cd.mono_tx_count;
        return h;
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        std::vector<uint8_t> modified_coinbase;
        uint256 new_merkle_root;
        InjectTagComputeRoot(coinbase_data, merge_mining_tag, modified_coinbase, new_merkle_root);

        MoneroBlockHeader header = SnapshotHeader(coinbase_data);
        header.merkle_root = new_merkle_root;

        return HexStr(header.BuildHashingBlob());
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& seed_hash
    ) override {
        uint256 hash;
        auto& miner = node::GetRandomXMiner();

        // Initialize RandomX with seed if needed
        if (!seed_hash.empty() && miner.IsInitialized()) {
            // TODO: handle seed changes
        }

        if (miner.IsInitialized()) {
            miner.CalculateHash(hashing_blob.data(), hashing_blob.size(), hash.data());
        } else {
            hash = Hash(hashing_blob);
        }

        return hash;
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<MoneroBlockHeader>(m_current_header);
        header->merkle_root = coinbase_data.merkle_root;
        header->nonce = nonce;
        return header;
    }

    bool SubmitBlock(const std::string& block_blob) override {
        std::string response = HttpPost("/json_rpc",
            "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_block\",\"params\":[\"" + block_blob + "\"]}");

        // monerod pretty-prints its JSON ("status": "OK") — tolerate any spacing,
        // and treat an error object as failure even if "OK" appears elsewhere.
        if (response.find("\"error\"") != std::string::npos) return false;
        return ParseJsonString(response, "status") == "OK";
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& /*extra_data*/ = ""
    ) override {
        CAuxPow proof;

        // Rebuild the SAME tag-injected coinbase + tree root the miner committed to
        // in BuildHashingBlob, from the frozen snapshot — so the daemon reconstructs
        // a byte-identical 76-byte RandomX blob (only the winning nonce differs).
        std::vector<uint8_t> modified_coinbase;
        uint256 new_merkle_root;
        InjectTagComputeRoot(coinbase_data, merge_mining_tag, modified_coinbase, new_merkle_root);

        proof.parentBlock.major_version = coinbase_data.mono_major;
        proof.parentBlock.minor_version = coinbase_data.mono_minor;
        proof.parentBlock.timestamp     = coinbase_data.mono_timestamp;
        proof.parentBlock.prev_id       = coinbase_data.mono_prev_id;
        proof.parentBlock.nonce         = nonce;
        proof.parentBlock.merkle_root   = new_merkle_root;
        proof.parentBlock.seed_hash     = coinbase_data.mono_seed;  // raw RandomX key bytes
        proof.parentBlock.num_txs       = coinbase_data.mono_tx_count;

        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::RANDOMX);
        // For RANDOMX the PoW hash is recomputed from parentBlock (76-byte blob), so
        // parentHeaderRaw is free to carry the monero coinbase bytes that the
        // monero-aware CAuxPow::Check needs (tag substring + tree-root proof).
        proof.parentHeaderRaw = modified_coinbase;
        proof.coinbaseBranch.vHash  = coinbase_data.merkle_branch;
        proof.coinbaseBranch.nIndex = 0;
        proof.nChainId = m_config.chain_id;

        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        if (difficulty == 0) difficulty = 1;

        // Monero: target = (2^256 - 1) / difficulty
        uint256 max_uint256;
        std::memset(max_uint256.data(), 0xff, 32);
        arith_uint256 max_target = UintToArith256(max_uint256);
        arith_uint256 target = max_target / difficulty;
        return ArithToUint256(target);
    }

private:
    MoneroBlockHeader m_current_header;
    uint64_t m_current_height{0};
    std::string m_seed_hash;
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_MONERO_H
