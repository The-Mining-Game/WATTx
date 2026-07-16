// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_BITCOIN_H
#define WATTX_STRATUM_PARENT_CHAIN_BITCOIN_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <streams.h>
#include <uint256.h>

namespace merged_stratum {

/**
 * Bitcoin-style block header (80 bytes)
 * Used by Bitcoin, Bitcoin Cash, Bitcoin SV, and other SHA256d chains
 */
class BitcoinBlockHeader : public IParentBlockHeader {
public:
    int32_t nVersion{0};
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint32_t nNonce{0};

    uint256 GetHash() const override {
        // SHA256d of the 80-byte header
        std::vector<uint8_t> data = Serialize();
        return Hash(data);
    }

    uint256 GetPoWHash() const override {
        // For Bitcoin, PoW hash is same as block hash (SHA256d)
        return GetHash();
    }

    std::vector<uint8_t> Serialize() const override {
        std::vector<uint8_t> data;
        data.reserve(80);

        // Version (4 bytes, little-endian)
        data.push_back(nVersion & 0xFF);
        data.push_back((nVersion >> 8) & 0xFF);
        data.push_back((nVersion >> 16) & 0xFF);
        data.push_back((nVersion >> 24) & 0xFF);

        // Previous block hash (32 bytes)
        data.insert(data.end(), hashPrevBlock.begin(), hashPrevBlock.end());

        // Merkle root (32 bytes)
        data.insert(data.end(), hashMerkleRoot.begin(), hashMerkleRoot.end());

        // Time (4 bytes, little-endian)
        data.push_back(nTime & 0xFF);
        data.push_back((nTime >> 8) & 0xFF);
        data.push_back((nTime >> 16) & 0xFF);
        data.push_back((nTime >> 24) & 0xFF);

        // Bits (4 bytes, little-endian)
        data.push_back(nBits & 0xFF);
        data.push_back((nBits >> 8) & 0xFF);
        data.push_back((nBits >> 16) & 0xFF);
        data.push_back((nBits >> 24) & 0xFF);

        // Nonce (4 bytes, little-endian)
        data.push_back(nNonce & 0xFF);
        data.push_back((nNonce >> 8) & 0xFF);
        data.push_back((nNonce >> 16) & 0xFF);
        data.push_back((nNonce >> 24) & 0xFF);

        return data;
    }

    uint32_t GetNonce() const override { return nNonce; }
    void SetNonce(uint32_t nonce) override { nNonce = nonce; }

    static BitcoinBlockHeader Deserialize(const std::vector<uint8_t>& data) {
        BitcoinBlockHeader header;
        if (data.size() < 80) return header;

        size_t pos = 0;

        // Version
        header.nVersion = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;

        // Previous block hash
        std::memcpy(header.hashPrevBlock.data(), &data[pos], 32);
        pos += 32;

        // Merkle root
        std::memcpy(header.hashMerkleRoot.data(), &data[pos], 32);
        pos += 32;

        // Time
        header.nTime = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;

        // Bits
        header.nBits = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);
        pos += 4;

        // Nonce
        header.nNonce = data[pos] | (data[pos+1] << 8) | (data[pos+2] << 16) | (data[pos+3] << 24);

        return header;
    }
};

/**
 * Bitcoin/SHA256d parent chain handler
 * Supports Bitcoin, Bitcoin Cash, Bitcoin SV, and similar chains
 */
class BitcoinChainHandler : public ParentChainHandlerBase {
public:
    explicit BitcoinChainHandler(const ParentChainConfig& config)
        : ParentChainHandlerBase(config) {}

    bool GetBlockTemplate(
        std::string& hashing_blob,
        std::string& full_template,
        std::string& seed_hash,
        uint64_t& height,
        uint64_t& difficulty,
        ParentCoinbaseData& coinbase_data
    ) override {
        // Bitcoin uses getblocktemplate RPC
        std::string response = JsonRpcCall("getblocktemplate",
            "[{\"rules\":" + GetGbtRules() +
            ",\"capabilities\":[\"coinbasetxn\",\"workid\",\"coinbase/append\"]}]");

        if (response.empty()) {
            LogPrintf("BitcoinChain: Failed to get block template\n");
            return false;
        }

        // Parse response
        std::string version_str = ParseJsonString(response, "version");
        std::string prevhash = ParseJsonString(response, "previousblockhash");
        std::string bits_str = ParseJsonString(response, "bits");
        std::string height_str = ParseJsonString(response, "height");
        std::string target_str = ParseJsonString(response, "target");
        std::string curtime_str = ParseJsonString(response, "curtime");
        std::string coinbasetxn = ParseJsonString(response, "coinbasetxn");

        if (prevhash.empty()) {
            LogPrintf("BitcoinChain: Invalid block template response\n");
            return false;
        }

        height = height_str.empty() ? 0 : std::stoull(height_str);

        // Parse coinbase transaction
        // Bitcoin's getblocktemplate returns coinbasetxn as hex
        std::string coinbase_hex = ParseJsonString(coinbasetxn.empty() ? response : coinbasetxn, "data");
        if (coinbase_hex.empty()) {
            // Try alternative field names
            coinbase_hex = ParseJsonString(response, "coinbase");
        }

        if (!coinbase_hex.empty()) {
            coinbase_data.coinbase_tx = ParseHex(coinbase_hex);
        }

        // Core daemons return no coinbasetxn — build a REAL coinbase paying the
        // pool's parent-chain address, so a winning share submits as a VALID
        // parent block (true merged mining: miner work earns the parent coin
        // AND WATTx). Layout:
        //   scriptSig = BIP34 height push | 34B MM-tag reserve | 8B extranonce
        // Coinbase-only block: no witness txs → no witness commitment required;
        // single tx → its txid IS the merkle root (empty branch everywhere).
        if (coinbase_data.coinbase_tx.empty() && !m_config.wallet_address.empty()) {
            if (m_payout_spk.empty()) {
                std::string va = JsonRpcCall("validateaddress",
                                             "[\"" + m_config.wallet_address + "\"]");
                m_payout_spk = ParseHex(ParseJsonString(va, "scriptPubKey"));
            }
            std::string cbv_str = ParseJsonString(response, "coinbasevalue");
            uint64_t cbvalue = cbv_str.empty() ? 0 : std::stoull(cbv_str);
            uint64_t h = height_str.empty() ? 0 : std::stoull(height_str);

            if (!m_payout_spk.empty() && m_payout_spk.size() < 0xFD && cbvalue > 0 && h > 0) {
                // BIP34: minimal CScriptNum encoding of the height, pushed first
                std::vector<uint8_t> hb;
                for (uint64_t v = h; v; v >>= 8) hb.push_back(v & 0xFF);
                if (hb.back() & 0x80) hb.push_back(0x00);

                std::vector<uint8_t> ss;
                ss.push_back(static_cast<uint8_t>(hb.size()));
                ss.insert(ss.end(), hb.begin(), hb.end());
                size_t tag_off = ss.size();
                ss.insert(ss.end(), 34, 0x00);   // MM tag reserve
                size_t en_off = ss.size();
                ss.insert(ss.end(), 8, 0x00);    // extranonce region

                std::vector<uint8_t> tx;
                auto w32 = [&tx](uint32_t v) { for (int i = 0; i < 4; i++) tx.push_back((v >> (8*i)) & 0xFF); };
                auto w64 = [&tx](uint64_t v) { for (int i = 0; i < 8; i++) tx.push_back((v >> (8*i)) & 0xFF); };
                w32(2);                            // tx version
                tx.push_back(0x01);                // vin count
                tx.insert(tx.end(), 32, 0x00);     // prevout hash (null)
                w32(0xffffffff);                   // prevout index
                tx.push_back(static_cast<uint8_t>(ss.size()));
                size_t ss_base = tx.size();
                tx.insert(tx.end(), ss.begin(), ss.end());
                w32(0xffffffff);                   // sequence
                tx.push_back(0x01);                // vout count
                w64(cbvalue);
                tx.push_back(static_cast<uint8_t>(m_payout_spk.size()));
                tx.insert(tx.end(), m_payout_spk.begin(), m_payout_spk.end());
                w32(0);                            // locktime

                coinbase_data.coinbase_tx       = tx;
                coinbase_data.reserve_offset    = ss_base + tag_off;
                coinbase_data.reserve_size      = 34;
                coinbase_data.extranonce_offset = ss_base + en_off;
                m_real_coinbase = true;
            }
        }

        // Build header for hashing
        BitcoinBlockHeader header;
        header.nVersion = version_str.empty() ? 0x20000000 : std::stoi(version_str);
        header.hashPrevBlock = uint256::FromHex(prevhash).value_or(uint256{});
        header.nTime = curtime_str.empty() ? GetTime() : std::stoul(curtime_str);
        header.nBits = bits_str.empty() ? 0 : std::stoul(bits_str, nullptr, 16);
        header.nNonce = 0;

        // Store parsed data
        m_current_header = header;
        m_current_prevhash = prevhash;
        m_current_bits = bits_str;
        m_current_height = height;

        // Snapshot the header fields into the job's coinbase_data so the mined
        // header and the AuxPoW proof are rebuilt from the SAME frozen values,
        // immune to poller refreshes of m_current_header (see ParentCoinbaseData).
        coinbase_data.parent_version  = header.nVersion;
        coinbase_data.parent_prevhash = header.hashPrevBlock;
        coinbase_data.parent_time     = header.nTime;
        coinbase_data.parent_bits     = header.nBits;
        coinbase_data.parent_height   = height;
        coinbase_data.header_snapshot = true;

        // Calculate difficulty from target
        if (!target_str.empty()) {
            uint256 target = uint256::FromHex(target_str).value_or(uint256{});
            coinbase_data.parent_target = target;  // exact target for meets_parent
            // difficulty = max_target / target
            arith_uint256 target_arith = UintToArith256(target);
            if (target_arith > 0) {
                arith_uint256 max_target;
                max_target.SetCompact(0x1d00ffff);  // Bitcoin max target
                difficulty = (max_target / target_arith).GetLow64();
            } else {
                difficulty = 1;
            }
        }

        // Build hashing blob (80-byte header)
        auto header_data = header.Serialize();
        hashing_blob = HexStr(header_data);

        // Parse raw non-coinbase transactions from the "transactions" JSON array.
        // With a REAL pool coinbase the block is coinbase-only: including template
        // txs would require the witness commitment + a real merkle branch; a
        // coinbase-only block is fully valid (merely forgoes fees) and keeps the
        // single-tx merkle assumption (txid == root) everywhere.
        coinbase_data.raw_transactions.clear();
        size_t tx_arr = coinbase_data.extranonce_offset > 0
            ? std::string::npos : response.find("\"transactions\":[");
        if (tx_arr != std::string::npos) {
            tx_arr += 16;
            size_t tx_end = response.find(']', tx_arr);
            if (tx_end != std::string::npos) {
                std::string arr = response.substr(tx_arr, tx_end - tx_arr);
                size_t p = 0;
                while (p < arr.size()) {
                    size_t ob = arr.find('{', p);
                    if (ob == std::string::npos) break;
                    // Find matching close brace (handle nesting)
                    int depth = 1; size_t cb = ob + 1;
                    while (cb < arr.size() && depth > 0) {
                        if (arr[cb] == '{') depth++;
                        else if (arr[cb] == '}') depth--;
                        cb++;
                    }
                    std::string obj = arr.substr(ob, cb - ob);
                    std::string tx_hex = ParseJsonString(obj, "data");
                    if (!tx_hex.empty()) {
                        coinbase_data.raw_transactions.push_back(ParseHex(tx_hex));
                    }
                    p = cb;
                }
            }
        }

        full_template = response;
        seed_hash = "";  // Not used for SHA256d

        LogPrintf("BitcoinChain: Got template at height %lu, %zu txs\n",
                  height, coinbase_data.raw_transactions.size());
        return true;
    }

    bool ParseBlockTemplate(
        const std::string& template_blob,
        ParentCoinbaseData& coinbase_data
    ) override {
        std::vector<uint8_t> data = ParseHex(template_blob);
        if (data.size() < 80) return false;

        // For Bitcoin, we need to parse the block structure:
        // - 80 byte header
        // - varint tx count
        // - transactions (first is coinbase)

        size_t pos = 80;  // Skip header

        // Transaction count
        uint64_t tx_count;
        pos += ReadVarint(data, pos, tx_count);

        if (tx_count == 0) return false;

        // Parse coinbase transaction
        size_t coinbase_start = pos;

        // TX: version (4), inputs, outputs, locktime (4)
        pos += 4;  // version

        // Check for witness marker
        bool has_witness = false;
        if (pos + 2 <= data.size() && data[pos] == 0x00 && data[pos+1] == 0x01) {
            has_witness = true;
            pos += 2;
        }

        // Input count
        uint64_t vin_count;
        pos += ReadVarint(data, pos, vin_count);

        // Skip inputs
        for (uint64_t i = 0; i < vin_count; i++) {
            pos += 36;  // prevout (32 + 4)
            uint64_t script_len;
            pos += ReadVarint(data, pos, script_len);
            coinbase_data.reserve_offset = pos;  // scriptSig is where MM tag goes
            coinbase_data.reserve_size = script_len;
            pos += script_len;  // scriptSig
            pos += 4;  // sequence
        }

        // Output count
        uint64_t vout_count;
        pos += ReadVarint(data, pos, vout_count);

        // Skip outputs
        for (uint64_t i = 0; i < vout_count; i++) {
            pos += 8;  // value
            uint64_t script_len;
            pos += ReadVarint(data, pos, script_len);
            pos += script_len;  // scriptPubKey
        }

        // Skip witness data if present
        if (has_witness) {
            for (uint64_t i = 0; i < vin_count; i++) {
                uint64_t witness_count;
                pos += ReadVarint(data, pos, witness_count);
                for (uint64_t j = 0; j < witness_count; j++) {
                    uint64_t item_len;
                    pos += ReadVarint(data, pos, item_len);
                    pos += item_len;
                }
            }
        }

        pos += 4;  // locktime

        // Store coinbase
        coinbase_data.coinbase_tx.assign(data.begin() + coinbase_start, data.begin() + pos);
        coinbase_data.coinbase_index = 0;

        // Parse remaining transactions for merkle tree
        std::vector<uint256> tx_hashes;
        tx_hashes.push_back(Hash(coinbase_data.coinbase_tx));

        while (pos < data.size()) {
            size_t tx_start = pos;
            // Simplified: just hash remaining data as one tx
            // In production, properly parse each transaction
            uint256 tx_hash = Hash(std::span<const uint8_t>(data.data() + tx_start, data.size() - tx_start));
            tx_hashes.push_back(tx_hash);
            break;  // Simplified
        }

        coinbase_data.merkle_branch = BuildMerkleBranch(tx_hashes, 0);
        coinbase_data.merkle_root = CalculateMerkleRoot(tx_hashes);

        return true;
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        // The miner grinds this exact 80-byte header. Its merkle root commits to
        // the parent coinbase carrying the WATTx merge-mining tag — the REAL
        // pool-paying coinbase when GetBlockTemplate built one (true merged
        // mining), else the synthetic fallback — and every other field comes from
        // the per-job header snapshot, so the AuxPoW proof built later in
        // CreateAuxPow reproduces these identical bytes.
        uint256 merkle_root;
        if (!coinbase_data.coinbase_tx.empty() && coinbase_data.extranonce_offset > 0 &&
            coinbase_data.reserve_offset + merge_mining_tag.size() <= coinbase_data.coinbase_tx.size()) {
            std::vector<uint8_t> cbv = coinbase_data.coinbase_tx;
            std::memcpy(cbv.data() + coinbase_data.reserve_offset,
                        merge_mining_tag.data(), merge_mining_tag.size());
            merkle_root = Hash(cbv);  // legacy-serialized single tx: sha256d == txid
        } else {
            CMutableTransaction cb = BuildAuxMergedCoinbase(merge_mining_tag, coinbase_data.parent_height);
            merkle_root = CTransaction(cb).GetHash();
        }

        std::vector<uint8_t> raw = BuildBitcoinHeader(
            static_cast<uint32_t>(coinbase_data.parent_version),
            coinbase_data.parent_prevhash, merkle_root,
            coinbase_data.parent_time, coinbase_data.parent_bits, /*nonce=*/0);
        return HexStr(raw);
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& /* seed_hash */
    ) override {
        // SHA256d
        return Hash(hashing_blob);
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<BitcoinBlockHeader>(m_current_header);
        header->hashMerkleRoot = coinbase_data.merkle_root;
        header->nNonce = nonce;
        return header;
    }

    bool SubmitBlock(const std::string& block_blob) override {
        std::string response = JsonRpcCall("submitblock", "[\"" + block_blob + "\"]");
        // Bitcoin returns null on success
        return response.find("\"result\":null") != std::string::npos ||
               response.find("\"result\": null") != std::string::npos;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& /*wattx_header*/,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& extra_data = ""
    ) override {
        CAuxPow proof;

        // Bitcoin-stratum submits carry "extranonce8_hex:ntime8_hex" in extra_data
        // so the proof rebuilds the miner's exact coinbase (per-miner extranonce)
        // and header time. XMRig submits leave it empty: zero extranonce, snapshot
        // ntime — matching BuildHashingBlob byte-for-byte.
        std::vector<uint8_t> extranonce;
        uint32_t time_val = coinbase_data.parent_time;
        if (size_t colon = extra_data.find(':'); colon != std::string::npos) {
            extranonce = ParseHex(extra_data.substr(0, colon));
            time_val = static_cast<uint32_t>(
                strtoul(extra_data.substr(colon + 1).c_str(), nullptr, 16));
        }

        // Rebuild the SAME coinbase the miner committed to in BuildHashingBlob —
        // the REAL pool-paying coinbase (tag + per-miner extranonce patched in)
        // when one was built, else the synthetic fallback — so its txid, the
        // single-tx merkle root, matches the mined header exactly.
        CMutableTransaction cb;
        uint256 merkle_root;
        if (!coinbase_data.coinbase_tx.empty() && coinbase_data.extranonce_offset > 0 &&
            coinbase_data.reserve_offset + merge_mining_tag.size() <= coinbase_data.coinbase_tx.size() &&
            coinbase_data.extranonce_offset + 8 <= coinbase_data.coinbase_tx.size()) {
            std::vector<uint8_t> cbv = coinbase_data.coinbase_tx;
            std::memcpy(cbv.data() + coinbase_data.reserve_offset,
                        merge_mining_tag.data(), merge_mining_tag.size());
            if (!extranonce.empty()) {
                std::memcpy(cbv.data() + coinbase_data.extranonce_offset,
                            extranonce.data(), std::min<size_t>(extranonce.size(), 8));
            }
            merkle_root = Hash(cbv);
            DataStream ds{cbv};
            ds >> TX_NO_WITNESS(cb);
        } else {
            cb = BuildAuxMergedCoinbase(
                merge_mining_tag, coinbase_data.parent_height,
                extranonce.empty() ? nullptr : &extranonce);
            merkle_root = CTransaction(cb).GetHash();
        }

        // parentBlock carries merkle_root for Check() and timestamp for time validation
        proof.parentBlock.timestamp   = time_val;
        proof.parentBlock.merkle_root = merkle_root;

        // Raw 80-byte Bitcoin header for SHA256d PoW verification — identical to
        // the mined blob except for the winning nonce supplied by the miner.
        proof.parentAlgoId    = static_cast<uint8_t>(AuxPowAlgo::SHA256D);
        proof.parentHeaderRaw = BuildBitcoinHeader(
            static_cast<uint32_t>(coinbase_data.parent_version),
            coinbase_data.parent_prevhash, merkle_root,
            time_val, coinbase_data.parent_bits, nonce);

        // Single-transaction block: the coinbase IS the merkle root, empty branch.
        proof.coinbaseTxMut = cb;
        proof.coinbaseBranch.vHash.clear();
        proof.coinbaseBranch.nIndex = 0;
        proof.nChainId = m_config.chain_id;

        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        // Bitcoin: target = max_target / difficulty
        // max_target = 0x00000000FFFF0000...
        if (difficulty == 0) difficulty = 1;

        arith_uint256 max_target;
        max_target.SetCompact(0x1d00ffff);  // Bitcoin's max target
        arith_uint256 target = max_target / difficulty;
        return ArithToUint256(target);
    }

protected:
    // GBT rules array; subclasses override for chains with extra required rules
    // (litecoind refuses GBT without "mweb").
    virtual std::string GetGbtRules() const { return "[\"segwit\"]"; }

    // Pool payout scriptPubKey on the parent chain (from validateaddress, cached)
    std::vector<uint8_t> m_payout_spk;
    // True once GetBlockTemplate built a REAL parent coinbase (vs synthetic)
    bool m_real_coinbase{false};

    BitcoinBlockHeader m_current_header;

private:
    std::string m_current_prevhash;
    std::string m_current_bits;
    uint64_t m_current_height{0};
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_BITCOIN_H
