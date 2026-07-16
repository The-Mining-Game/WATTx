// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_BASE_H
#define WATTX_STRATUM_PARENT_CHAIN_BASE_H

#include <stratum/parent_chain.h>
#include <hash.h>
#include <logging.h>
#include <util/strencodings.h>

#include <cstring>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace merged_stratum {

/**
 * Base implementation with common HTTP/RPC functionality
 */
class ParentChainHandlerBase : public IParentChainHandler {
public:
    explicit ParentChainHandlerBase(const ParentChainConfig& config)
        : m_config(config) {}

    std::string GetName() const override { return m_config.name; }
    ParentChainAlgo GetAlgo() const override { return m_config.algo; }
    uint32_t GetChainId() const override { return m_config.chain_id; }

    std::string HttpPost(const std::string& path, const std::string& body) override {
        // Resolve host with getaddrinfo (thread-safe, unlike gethostbyname)
        struct addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        std::string port_str = std::to_string(m_config.daemon_port);
        struct addrinfo* res = nullptr;
        if (getaddrinfo(m_config.daemon_host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
            if (res) freeaddrinfo(res);
            return "";
        }

        int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock < 0) {
            freeaddrinfo(res);
            return "";
        }

#ifdef WIN32
        DWORD timeout_ms = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            freeaddrinfo(res);
#ifdef WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return "";
        }
        freeaddrinfo(res);

        // Build HTTP request
        std::string auth_header;
        if (!m_config.daemon_user.empty()) {
            std::string credentials = m_config.daemon_user + ":" + m_config.daemon_password;
            auth_header = "Authorization: Basic " + EncodeBase64(credentials) + "\r\n";
        }

        std::ostringstream request;
        request << "POST " << path << " HTTP/1.1\r\n";
        request << "Host: " << m_config.daemon_host << ":" << m_config.daemon_port << "\r\n";
        request << "Content-Type: application/json\r\n";
        request << auth_header;
        request << "Content-Length: " << body.length() << "\r\n";
        request << "Connection: close\r\n\r\n";
        request << body;

        std::string req_str = request.str();
        if (send(sock, req_str.c_str(), req_str.length(), 0) < 0) {
#ifdef WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return "";
        }

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

        // Extract body (skip headers)
        size_t body_start = response.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            return response.substr(body_start + 4);
        }

        return response;
    }

    std::string JsonRpcCall(const std::string& method, const std::string& params) override {
        std::ostringstream request;
        request << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"" << method << "\",\"params\":" << params << "}";
        return HttpPost("/", request.str());
    }

protected:
    ParentChainConfig m_config;

    // Helper: Read varint from buffer
    static size_t ReadVarint(const std::vector<uint8_t>& data, size_t pos, uint64_t& value) {
        value = 0;
        size_t bytes_read = 0;
        int shift = 0;
        while (pos + bytes_read < data.size()) {
            uint8_t byte = data[pos + bytes_read];
            bytes_read++;
            value |= (uint64_t)(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
            if (shift > 63) break;
        }
        return bytes_read;
    }

    // Helper: Write varint to buffer
    static void WriteVarint(std::vector<uint8_t>& data, uint64_t value) {
        while (value >= 0x80) {
            data.push_back((value & 0x7F) | 0x80);
            value >>= 7;
        }
        data.push_back(static_cast<uint8_t>(value));
    }

    // Helper: Calculate merkle root from transaction hashes
    static uint256 CalculateMerkleRoot(const std::vector<uint256>& hashes) {
        if (hashes.empty()) return uint256();
        if (hashes.size() == 1) return hashes[0];

        std::vector<uint256> tree = hashes;
        while (tree.size() > 1) {
            std::vector<uint256> next_level;
            for (size_t i = 0; i < tree.size(); i += 2) {
                if (i + 1 < tree.size()) {
                    next_level.push_back(Hash(tree[i], tree[i + 1]));
                } else {
                    next_level.push_back(Hash(tree[i], tree[i]));
                }
            }
            tree = std::move(next_level);
        }
        return tree[0];
    }

    // Helper: Build merkle branch for index
    static std::vector<uint256> BuildMerkleBranch(const std::vector<uint256>& hashes, int index) {
        std::vector<uint256> branch;
        if (hashes.size() <= 1) return branch;

        std::vector<uint256> tree = hashes;
        int idx = index;

        while (tree.size() > 1) {
            int sibling_idx = (idx & 1) ? idx - 1 : idx + 1;
            if (sibling_idx < (int)tree.size()) {
                branch.push_back(tree[sibling_idx]);
            } else {
                branch.push_back(tree[idx]);
            }

            std::vector<uint256> next_level;
            for (size_t i = 0; i < tree.size(); i += 2) {
                if (i + 1 < tree.size()) {
                    next_level.push_back(Hash(tree[i], tree[i + 1]));
                } else {
                    next_level.push_back(Hash(tree[i], tree[i]));
                }
            }
            tree = std::move(next_level);
            idx >>= 1;
        }

        return branch;
    }

    // Build the synthetic parent coinbase that carries the WATTx merge-mining
    // commitment. Deterministic from (tag, height) so a handler's BuildHashingBlob
    // (the header the miner grinds) and CreateAuxPow (the proof the validator
    // checks) commit to a byte-identical coinbase — and therefore an identical
    // single-tx merkle root. Every Bitcoin-style handler (SHA256d, Scrypt, X11,
    // Equihash, kHeavyHash) must use THIS so the two paths never desync.
    //
    // The MM tag is placed FIRST in the scriptSig: TX_EXTRA_MERGE_MINING_TAG is
    // 0x03, which is also the "push 3 bytes" opcode of a BIP34 height prefix —
    // ParseMergeMiningTag scans for the first 0x03, so the tag must precede any
    // height push or the height would be misread as the commitment.
    //
    // The scriptSig ends with an AUX_COINBASE_EXTRANONCE_SIZE-byte extranonce
    // region: zeros for XMRig-protocol miners (who grind only the header nonce),
    // filled per-miner for Bitcoin-stratum clients, which rebuild the coinbase
    // from coinb1 + extranonce1 + extranonce2 + coinb2 and derive their own
    // merkle root from it. It sits LAST so the tag scan and height parse are
    // unaffected by its content.
public:
    static constexpr size_t AUX_COINBASE_EXTRANONCE_SIZE = 8;

    static CMutableTransaction BuildAuxMergedCoinbase(
        const std::vector<uint8_t>& merge_mining_tag, uint64_t height,
        const std::vector<uint8_t>* extranonce = nullptr)
    {
        CMutableTransaction cb;
        cb.version = 2;

        CTxIn in;
        in.prevout.SetNull();
        std::vector<uint8_t> ss(merge_mining_tag.begin(), merge_mining_tag.end());
        ss.push_back(0x03);                      // BIP34-style height, AFTER the tag
        ss.push_back(height & 0xFF);
        ss.push_back((height >> 8) & 0xFF);
        ss.push_back((height >> 16) & 0xFF);
        for (size_t i = 0; i < AUX_COINBASE_EXTRANONCE_SIZE; ++i) {
            ss.push_back(extranonce && i < extranonce->size() ? (*extranonce)[i] : 0x00);
        }
        in.scriptSig = CScript(ss.begin(), ss.end());
        in.nSequence = 0xffffffff;
        cb.vin.push_back(in);

        CTxOut out;
        out.nValue = 0;
        cb.vout.push_back(out);

        return cb;
    }

    // Build an 80-byte Bitcoin-style LE header from its 6 fields.
    // Used by SHA256d, Scrypt, X11, and kHeavyHash handlers for parentHeaderRaw.
    static std::vector<uint8_t> BuildBitcoinHeader(uint32_t version,
                                                    const uint256& prevhash,
                                                    const uint256& merkle_root,
                                                    uint32_t time,
                                                    uint32_t bits,
                                                    uint32_t nonce) {
        std::vector<uint8_t> raw(80);
        auto w32 = [&](int off, uint32_t v) {
            raw[off]   =  v        & 0xFF;
            raw[off+1] = (v >>  8) & 0xFF;
            raw[off+2] = (v >> 16) & 0xFF;
            raw[off+3] = (v >> 24) & 0xFF;
        };
        w32(0, version);
        std::memcpy(raw.data() +  4, prevhash.begin(),    32);
        std::memcpy(raw.data() + 36, merkle_root.begin(), 32);
        w32(68, time);
        w32(72, bits);
        w32(76, nonce);
        return raw;
    }

    // Helper: Parse JSON string value
    static std::string ParseJsonString(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";

        pos += search.length();
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

        if (pos >= json.length()) return "";

        if (json[pos] == '"') {
            pos++;
            size_t end = json.find('"', pos);
            if (end == std::string::npos) return "";
            return json.substr(pos, end - pos);
        }

        size_t end = json.find_first_of(",}]", pos);
        if (end == std::string::npos) end = json.length();
        std::string value = json.substr(pos, end - pos);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
            value.pop_back();
        return value;
    }
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_BASE_H
