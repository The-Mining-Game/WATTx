// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_KASPA_H
#define WATTX_STRATUM_PARENT_CHAIN_KASPA_H

#include <stratum/parent_chain_base.h>
#include <arith_uint256.h>
#include <crypto/sha256.h>

// kHeavyHash stub - TODO: implement actual kHeavyHash algorithm
inline void kheavyhash(const void* input, size_t len, void* output) {
    // Placeholder: use SHA256d until proper kHeavyHash is implemented
    CSHA256 sha;
    sha.Write(static_cast<const unsigned char*>(input), len);
    unsigned char hash1[32];
    sha.Finalize(hash1);
    sha.Reset();
    sha.Write(hash1, 32);
    sha.Finalize(static_cast<unsigned char*>(output));
}

namespace merged_stratum {

/**
 * Kaspa block header
 * Kaspa uses a DAG-based BlockDAG structure, not a linear chain
 * This is simplified for merged mining purposes
 */
class KaspaBlockHeader : public IParentBlockHeader {
public:
    uint16_t version{0};
    std::vector<uint256> parentHashes;     // Multiple parents in DAG
    uint256 hashMerkleRoot;
    uint256 acceptedIdMerkleRoot;
    uint256 utxoCommitment;
    uint64_t timestamp{0};
    uint32_t bits{0};
    uint64_t nonce{0};                      // 64-bit nonce
    uint256 daaScore;
    uint64_t blueScore{0};
    std::vector<uint8_t> blueWork;
    std::vector<uint8_t> pruningPoint;

    uint256 GetHash() const override {
        // Kaspa uses blake2b for hashing
        std::vector<uint8_t> data = Serialize();
        return Hash(data);  // Simplified - should use blake2b
    }

    uint256 GetPoWHash() const override {
        // Kaspa uses kHeavyHash
        std::vector<uint8_t> prePoW = SerializePrePoW();

        uint256 hash;
        kheavyhash(prePoW.data(), prePoW.size(), hash.data());

        return hash;
    }

    // Serialize the pre-PoW header (without nonce for mining)
    std::vector<uint8_t> SerializePrePoW() const {
        std::vector<uint8_t> data;
        data.reserve(200);

        // Version (2 bytes)
        data.push_back(version & 0xFF);
        data.push_back((version >> 8) & 0xFF);

        // Parent count and hashes
        uint64_t parent_count = parentHashes.size();
        data.push_back(parent_count & 0xFF);
        for (const auto& parent : parentHashes) {
            data.insert(data.end(), parent.begin(), parent.end());
        }

        // Merkle roots
        data.insert(data.end(), hashMerkleRoot.begin(), hashMerkleRoot.end());
        data.insert(data.end(), acceptedIdMerkleRoot.begin(), acceptedIdMerkleRoot.end());
        data.insert(data.end(), utxoCommitment.begin(), utxoCommitment.end());

        // Timestamp (8 bytes)
        for (int i = 0; i < 8; i++) {
            data.push_back((timestamp >> (i * 8)) & 0xFF);
        }

        // Bits (4 bytes)
        data.push_back(bits & 0xFF);
        data.push_back((bits >> 8) & 0xFF);
        data.push_back((bits >> 16) & 0xFF);
        data.push_back((bits >> 24) & 0xFF);

        return data;
    }

    std::vector<uint8_t> Serialize() const override {
        std::vector<uint8_t> data = SerializePrePoW();

        // Nonce (8 bytes)
        for (int i = 0; i < 8; i++) {
            data.push_back((nonce >> (i * 8)) & 0xFF);
        }

        // DAA score
        data.insert(data.end(), daaScore.begin(), daaScore.end());

        // Blue score (8 bytes)
        for (int i = 0; i < 8; i++) {
            data.push_back((blueScore >> (i * 8)) & 0xFF);
        }

        // Blue work and pruning point
        data.push_back(blueWork.size() & 0xFF);
        data.insert(data.end(), blueWork.begin(), blueWork.end());

        data.push_back(pruningPoint.size() & 0xFF);
        data.insert(data.end(), pruningPoint.begin(), pruningPoint.end());

        return data;
    }

    uint32_t GetNonce() const override {
        return static_cast<uint32_t>(nonce & 0xFFFFFFFF);
    }

    void SetNonce(uint32_t n) override {
        nonce = n;
    }

    void SetNonce64(uint64_t n) {
        nonce = n;
    }
};

/**
 * Kaspa/kHeavyHash parent chain handler
 * Note: Kaspa uses a different RPC interface (gRPC/REST, not JSON-RPC)
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
        // Kaspa uses REST API for mining
        // GET /info/getBlockTemplate
        std::string response = HttpGet("/info/getBlockTemplate?payAddress=" + m_config.wallet_address);

        if (response.empty()) {
            LogPrintf("KaspaChain: Failed to get block template\n");
            return false;
        }

        // Parse Kaspa-specific response format
        std::string block_str = ParseJsonString(response, "block");
        std::string header_str = ParseJsonString(block_str.empty() ? response : block_str, "header");

        if (header_str.empty()) {
            LogPrintf("KaspaChain: Invalid block template response\n");
            return false;
        }

        // Parse header fields
        m_current_header.version = 1;

        std::string hash_merkle = ParseJsonString(header_str, "hashMerkleRoot");
        if (!hash_merkle.empty()) {
            m_current_header.hashMerkleRoot = uint256::FromHex(hash_merkle).value_or(uint256{});
        }

        std::string timestamp_str = ParseJsonString(header_str, "timestamp");
        if (!timestamp_str.empty()) {
            m_current_header.timestamp = std::stoull(timestamp_str);
        }

        std::string bits_str = ParseJsonString(header_str, "bits");
        if (!bits_str.empty()) {
            m_current_header.bits = std::stoul(bits_str);
        }

        // Build hashing blob
        auto pre_pow = m_current_header.SerializePrePoW();
        hashing_blob = HexStr(pre_pow);

        full_template = response;
        seed_hash = "";
        height = 0;  // Kaspa doesn't have traditional height
        difficulty = 1;  // TODO: parse from response

        LogPrintf("KaspaChain: Got block template\n");
        return true;
    }

    bool ParseBlockTemplate(
        const std::string& template_blob,
        ParentCoinbaseData& coinbase_data
    ) override {
        // Kaspa doesn't have traditional coinbase transactions
        // It uses coinbase outputs in a different structure
        return true;
    }

    std::string BuildHashingBlob(
        const ParentCoinbaseData& /*coinbase_data*/,
        const std::vector<uint8_t>& merge_mining_tag
    ) override {
        // Commit the mined header to the synthetic coinbase carrying the WATTx
        // merge-mining tag (CreateAuxPow rebuilds the identical coinbase). We hash
        // the full serialization (nonce=0) so blob and parentHeaderRaw differ only
        // in the nonce region the miner grinds — required since the kHeavyHash PoW
        // check currently falls back to SHA256d over parentHeaderRaw.
        CMutableTransaction cb = BuildAuxMergedCoinbase(merge_mining_tag, m_current_header.blueScore);
        KaspaBlockHeader header = m_current_header;
        header.hashMerkleRoot = CTransaction(cb).GetHash();
        header.SetNonce(0);
        return HexStr(header.Serialize());
    }

    uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& /* seed_hash */
    ) override {
        uint256 hash;
        kheavyhash(hashing_blob.data(), hashing_blob.size(), hash.data());
        return hash;
    }

    std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) override {
        auto header = std::make_unique<KaspaBlockHeader>(m_current_header);
        header->SetNonce(nonce);
        return header;
    }

    bool SubmitBlock(const std::string& block_blob) override {
        // Kaspa uses POST /mining/submitBlock
        std::string body = "{\"block\":\"" + block_blob + "\"}";
        std::string response = HttpPost("/mining/submitBlock", body);
        return response.find("\"error\"") == std::string::npos;
    }

    CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& /*extra_data*/ = ""
    ) override {
        CAuxPow proof;

        // Rebuild the SAME synthetic coinbase committed by the mined header so its
        // txid is the merkle root of both, and include the nonce in parentHeaderRaw
        // so the (placeholder SHA256d) PoW check actually depends on the nonce.
        CMutableTransaction cb = BuildAuxMergedCoinbase(merge_mining_tag, m_current_header.blueScore);
        uint256 merkle_root = CTransaction(cb).GetHash();

        KaspaBlockHeader parent_header = m_current_header;
        parent_header.hashMerkleRoot = merkle_root;
        parent_header.SetNonce(nonce);

        // parentBlock: merkle_root for Check(), timestamp for time validation
        proof.parentBlock.timestamp   = parent_header.timestamp;
        proof.parentBlock.merkle_root = merkle_root;

        proof.parentAlgoId    = static_cast<uint8_t>(AuxPowAlgo::KHEAVYHASH);
        proof.parentHeaderRaw = parent_header.Serialize();  // includes nonce

        proof.coinbaseTxMut = cb;
        proof.coinbaseBranch.vHash.clear();
        proof.coinbaseBranch.nIndex = 0;
        proof.nChainId = m_config.chain_id;

        return proof;
    }

    uint256 DifficultyToTarget(uint64_t difficulty) override {
        if (difficulty == 0) difficulty = 1;

        // Kaspa uses different difficulty encoding
        uint256 max_target;
        std::memset(max_target.data(), 0xff, 32);
        arith_uint256 target = UintToArith256(max_target) / difficulty;
        return ArithToUint256(target);
    }

private:
    std::string HttpGet(const std::string& path) {
        // Simple HTTP GET (Kaspa uses REST, not JSON-RPC)
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return "";

#ifdef WIN32
        DWORD timeout_ms = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_config.daemon_port);

        struct hostent* he = gethostbyname(m_config.daemon_host.c_str());
        if (!he) {
#ifdef WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return "";
        }
        std::memcpy(&addr.sin_addr, he->h_addr, he->h_length);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
#ifdef WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return "";
        }

        std::ostringstream request;
        request << "GET " << path << " HTTP/1.1\r\n";
        request << "Host: " << m_config.daemon_host << "\r\n";
        request << "Connection: close\r\n\r\n";

        std::string req_str = request.str();
        send(sock, req_str.c_str(), req_str.length(), 0);

        std::string response;
        char buffer[4096];
        int bytes;
        while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes] = '\0';
            response += buffer;
        }

#ifdef WIN32
        closesocket(sock);
#else
        close(sock);
#endif

        size_t body_start = response.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            return response.substr(body_start + 4);
        }
        return response;
    }

    KaspaBlockHeader m_current_header;
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_KASPA_H
