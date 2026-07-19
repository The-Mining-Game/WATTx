// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_KASPA_H
#define WATTX_STRATUM_PARENT_CHAIN_KASPA_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>
#include <crypto/kheavyhash/kheavyhash.h>
#include <util/strencodings.h>

namespace merged_stratum {

/**
 * Kaspa / kHeavyHash parent chain handler — REAL merged mining via the kaspad
 * gRPC proxy (tools/kaspa_grpc.js, HTTP front-end for protowire MessageStream).
 *
 * Design: kaspad itself builds the tagged coinbase — the WATTx merge-mining
 * tag rides into GetBlockTemplate as extraData (hex-ASCII in the coinbase
 * payload), so PrepareTaggedTemplate refetches per job once the tag is known.
 * The proxy serves everything consensus needs: the keyed-blake2b BlockHash
 * preimage (+ field offsets), the serialized coinbase (TransactionHash
 * encoding) and its merkle branch, the pre-PoW hash, and the exact target.
 * Submission is by templateId: the proxy patches the miner's nonce into its
 * cached template and submits the real block over gRPC.
 *
 * Hashing blob (80 bytes, the kaspa miner form):
 *   [0..32)  pre_pow_hash (BlockHash of header with nonce=0, ts=0)
 *   [32..40) timestamp ms, LE
 *   [40..72) zero padding
 *   [72..80) nonce, LE (XMRig 4-byte nonces land in the low 4 bytes)
 */
class KaspaChainHandler : public ParentChainHandlerBase {
public:
    explicit KaspaChainHandler(const ParentChainConfig& config)
        : ParentChainHandlerBase(config) {}

    bool GetBlockTemplate(
        std::string& hashing_blob,
        std::string& full_template,
        std::string& seed_hash,
        uint64_t& height,
        uint64_t& difficulty,
        ParentCoinbaseData& coinbase_data
    ) override {
        std::string response = FetchTemplate("", coinbase_data);
        if (response.empty()) {
            LogPrintf("KaspaChain: Failed to get block template\n");
            return false;
        }
        hashing_blob = BuildBlobFromData(coinbase_data, 0);
        full_template = response;
        seed_hash = "";
        // daaScore is the closest thing to a height — the poller uses it for
        // "parent advanced" detection, which is exactly what daaScore tracks.
        height = m_last_daa_score;
        difficulty = 1;
        return true;
    }

    bool PrepareTaggedTemplate(
        ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        // extraData must be a protobuf `string` (UTF-8), so the raw 34-byte tag
        // travels hex-encoded; kaspad embeds those 68 ASCII bytes verbatim in
        // the coinbase payload. Consensus searches for the same ASCII form.
        std::string response = FetchTemplate(HexStr(merge_mining_tag), coinbase_data);
        if (response.empty()) {
            LogPrintf("KaspaChain: tagged template fetch failed — job keeps untagged template\n");
            return false;
        }
        return true;
    }

    bool ParseBlockTemplate(
        const std::string& /*template_blob*/,
        ParentCoinbaseData& /*coinbase_data*/
    ) override {
        return true;  // FetchTemplate parses everything already
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& /*merge_mining_tag*/
    ) override {
        // The tag is already inside the template coinbase (PrepareTaggedTemplate).
        return BuildBlobFromData(coinbase_data, 0);
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& /*seed_hash*/
    ) override {
        uint256 hash;
        if (hashing_blob.size() != 80) {
            std::memset(hash.begin(), 0xFF, 32);  // fail closed
            return hash;
        }
        uint64_t ts, nonce;
        std::memcpy(&ts, hashing_blob.data() + 32, 8);
        std::memcpy(&nonce, hashing_blob.data() + 72, 8);
        kheavyhash::Pow(hashing_blob.data(), ts, nonce, hash.begin());
        return hash;  // kaspa compares LE, same convention as UintToArith256
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& /*coinbase_data*/,
        uint32_t /*nonce*/
    ) override {
        return nullptr;  // kaspa submits by templateId, never by rebuilt header
    }

    // block_blob = "templateId:nonce_decimal" (built by the ValidateShare
    // KHEAVYHASH branch). The proxy patches its cached template and submits
    // the real block to kaspad over gRPC.
    bool SubmitBlock(const std::string& block_blob) override {
        size_t colon = block_blob.find(':');
        if (colon == std::string::npos) return false;
        std::string body = "{\"templateId\":\"" + block_blob.substr(0, colon) +
                           "\",\"nonce\":\"" + block_blob.substr(colon + 1) + "\"}";
        std::string response = HttpPost("/mining/submitBlock", body);
        return response.find("\"accepted\":true") != std::string::npos;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& /*wattx_header*/,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& /*merge_mining_tag*/,
        const std::string& extra_data = ""
    ) override {
        CAuxPow proof;
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::KHEAVYHASH);
        proof.nChainId = m_config.chain_id;

        // Patch the winning nonce into the preimage. extra_data carries the
        // submitted nonce bytes verbatim (LE, up to 8); fall back to the u32.
        std::vector<uint8_t> preimage = coinbase_data.kaspa_preimage;
        kheavyhash::HeaderPreimageInfo info;
        if (!preimage.empty() &&
            kheavyhash::ParseHeaderPreimage(preimage.data(), preimage.size(), info)) {
            std::vector<uint8_t> nb = ParseHex(extra_data);
            if (nb.empty()) {
                nb = {static_cast<uint8_t>(nonce & 0xFF),
                      static_cast<uint8_t>((nonce >> 8) & 0xFF),
                      static_cast<uint8_t>((nonce >> 16) & 0xFF),
                      static_cast<uint8_t>((nonce >> 24) & 0xFF)};
            }
            std::memset(preimage.data() + info.nonce_off, 0, 8);
            std::memcpy(preimage.data() + info.nonce_off, nb.data(),
                        std::min<size_t>(nb.size(), 8));
            std::memcpy(proof.parentBlock.merkle_root.begin(),
                        preimage.data() + info.merkle_root_off, 32);
        }

        // parentHeaderRaw = [u32 pre_len][preimage][u32 cb_len][coinbase][u8 n][32B x n]
        std::vector<uint8_t>& raw = proof.parentHeaderRaw;
        auto put_u32 = [&raw](uint32_t v) {
            raw.push_back(v & 0xFF); raw.push_back((v >> 8) & 0xFF);
            raw.push_back((v >> 16) & 0xFF); raw.push_back((v >> 24) & 0xFF);
        };
        put_u32(static_cast<uint32_t>(preimage.size()));
        raw.insert(raw.end(), preimage.begin(), preimage.end());
        put_u32(static_cast<uint32_t>(coinbase_data.coinbase_tx.size()));
        raw.insert(raw.end(), coinbase_data.coinbase_tx.begin(), coinbase_data.coinbase_tx.end());
        raw.push_back(static_cast<uint8_t>(coinbase_data.merkle_branch.size()));
        for (const auto& h : coinbase_data.merkle_branch) {
            raw.insert(raw.end(), h.begin(), h.end());
        }

        // kaspa timestamps are MILLISECONDS; parentBlock.timestamp only feeds the
        // parent-vs-aux time-window sanity check (seconds) — the PoW itself uses
        // the ms value inside the preimage.
        proof.parentBlock.timestamp = coinbase_data.kaspa_timestamp / 1000;
        proof.coinbaseBranch.vHash = coinbase_data.merkle_branch;
        proof.coinbaseBranch.nIndex = 0;
        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        if (difficulty == 0) difficulty = 1;
        uint256 max_target;
        std::memset(max_target.data(), 0xff, 32);
        arith_uint256 target = UintToArith256(max_target) / difficulty;
        return ArithToUint256(target);
    }

private:
    uint64_t m_last_daa_score{0};

    // Fetch a template from the proxy (optionally tagged) and snapshot every
    // field the job/consensus path needs into coinbase_data. Returns the raw
    // response, empty on failure.
    std::string FetchTemplate(const std::string& extra_data_hex,
                              ParentCoinbaseData& cb) {
        std::string path = "/info/getBlockTemplate?payAddress=" + m_config.wallet_address;
        if (!extra_data_hex.empty()) path += "&extraData=" + extra_data_hex;
        std::string response = HttpGet(path);
        if (response.empty()) return "";

        std::string template_id = ParseJsonString(response, "templateId");
        std::string preimage_hex = ParseJsonString(response, "headerPreimage");
        std::string prepow_hex = ParseJsonString(response, "prePowHash");
        std::string coinbase_hex = ParseJsonString(response, "coinbaseSer");
        std::string target_hex = ParseJsonString(response, "target");
        std::string ts_str = ParseJsonString(response, "timestampMs");
        std::string daa_str = ParseJsonString(response, "daaScore");
        if (template_id.empty() || preimage_hex.empty() || prepow_hex.empty() ||
            coinbase_hex.empty() || target_hex.empty() || ts_str.empty()) {
            LogPrintf("KaspaChain: template response missing fields\n");
            return "";
        }

        cb.kaspa_template_id = template_id;
        cb.kaspa_preimage = ParseHex(preimage_hex);
        cb.coinbase_tx = ParseHex(coinbase_hex);
        cb.kaspa_timestamp = strtoull(ts_str.c_str(), nullptr, 10);
        if (!daa_str.empty()) m_last_daa_score = strtoull(daa_str.c_str(), nullptr, 10);
        cb.parent_height = m_last_daa_score;

        // prePowHash / merkle branch are raw kaspa byte order — memcpy, never
        // uint256::FromHex (which stores display-reversed).
        std::vector<uint8_t> prepow = ParseHex(prepow_hex);
        if (prepow.size() != 32) return "";
        std::memcpy(cb.kaspa_prepow.begin(), prepow.data(), 32);

        cb.merkle_branch.clear();
        std::string branch_str = ParseJsonString(response, "merkleBranch");
        size_t start = 0;
        while (start < branch_str.size()) {
            size_t comma = branch_str.find(',', start);
            std::string one = branch_str.substr(start, comma == std::string::npos
                                                       ? std::string::npos : comma - start);
            std::vector<uint8_t> hb = ParseHex(one);
            if (hb.size() == 32) {
                uint256 h;
                std::memcpy(h.begin(), hb.data(), 32);
                cb.merkle_branch.push_back(h);
            }
            if (comma == std::string::npos) break;
            start = comma + 1;
        }

        // Exact template target (numeric compare via UintToArith256).
        cb.parent_target = uint256::FromHex(target_hex).value_or(uint256{});

        // Sanity: preimage must parse and its merkle-root/ts fields must agree.
        kheavyhash::HeaderPreimageInfo info;
        if (!kheavyhash::ParseHeaderPreimage(cb.kaspa_preimage.data(),
                                             cb.kaspa_preimage.size(), info)) {
            LogPrintf("KaspaChain: proxy preimage failed structural parse\n");
            return "";
        }
        return response;
    }

    std::string BuildBlobFromData(const ParentCoinbaseData& cb, uint64_t nonce) const {
        std::vector<uint8_t> blob(80, 0);
        std::memcpy(blob.data(), cb.kaspa_prepow.begin(), 32);
        uint64_t ts = cb.kaspa_timestamp;
        std::memcpy(blob.data() + 32, &ts, 8);
        std::memcpy(blob.data() + 72, &nonce, 8);
        return HexStr(blob);
    }
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_KASPA_H
