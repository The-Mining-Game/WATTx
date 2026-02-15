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
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return "";

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
