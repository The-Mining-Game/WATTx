// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/monero_wallet.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <sstream>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// Keccak-256 implementation (simplified)
extern "C" {
    // We'll use a basic keccak implementation
    void keccak(const uint8_t *in, size_t inlen, uint8_t *md, int mdlen);
}

// Ed25519 operations (simplified - in production, use libsodium or similar)
namespace ed25519 {
    // Curve order l = 2^252 + 27742317777372353535851937790883648493
    static const uint8_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    // Simplified scalar reduction mod l
    void sc_reduce32(uint8_t* s) {
        // This is a simplified version - production code should use
        // proper big integer arithmetic or libsodium's crypto_core_ed25519_scalar_reduce
        // For now, we just ensure the high bit is clear for valid ed25519 scalars
        s[31] &= 0x7f;
    }

    // Derive public key from secret key
    // In real implementation, this multiplies the base point by the scalar
    void derive_public_key(const uint8_t* secret, uint8_t* public_key) {
        // Simplified: hash the secret key to get a deterministic public key
        // Production code must use actual ed25519 point multiplication
        CSHA256 hasher;
        hasher.Write(secret, 32);
        hasher.Write((const uint8_t*)"ed25519_pk", 10);
        hasher.Finalize(public_key);
    }
}

namespace monero_wallet {

// ============================================================================
// Global Instance
// ============================================================================

static MoneroLightWallet g_monero_wallet;

MoneroLightWallet& GetMoneroWallet() {
    return g_monero_wallet;
}

// ============================================================================
// MoneroAccountKeys
// ============================================================================

bool MoneroAccountKeys::IsValid() const {
    // Check that keys are not all zeros
    bool spend_valid = false, view_valid = false;
    for (int i = 0; i < 32; i++) {
        if (spend_secret_key[i] != 0) spend_valid = true;
        if (view_secret_key[i] != 0) view_valid = true;
    }
    return spend_valid && view_valid;
}

void MoneroAccountKeys::Clear() {
    std::memset(spend_secret_key.data(), 0, 32);
    std::memset(spend_public_key.data(), 0, 32);
    std::memset(view_secret_key.data(), 0, 32);
    std::memset(view_public_key.data(), 0, 32);
}

// ============================================================================
// MoneroAddress
// ============================================================================

bool MoneroAddress::IsValid() const {
    return address.length() >= 95;
}

std::string MoneroAddress::GetShortAddress() const {
    if (address.length() < 12) return address;
    return address.substr(0, 6) + "..." + address.substr(address.length() - 6);
}

// ============================================================================
// MoneroLightWallet
// ============================================================================

MoneroLightWallet::MoneroLightWallet() = default;

MoneroLightWallet::~MoneroLightWallet() {
    m_keys.Clear();
}

bool MoneroLightWallet::InitFromSeed(const std::vector<uint8_t>& seed, MoneroNetworkType network) {
    if (seed.size() < 32) {
        LogPrintf("MoneroWallet: Seed too short\n");
        return false;
    }

    m_network = network;

    // Derive Monero spend key from WATTx seed
    // Use a domain separator to ensure different keys for different purposes
    CSHA256 hasher;
    hasher.Write(seed.data(), seed.size());
    hasher.Write((const uint8_t*)"monero_spend_key", 16);
    hasher.Finalize(m_keys.spend_secret_key.data());

    // Reduce to valid ed25519 scalar
    ScalarReduce(m_keys.spend_secret_key);

    // Derive view key from spend key (Monero standard)
    m_keys.view_secret_key = DeriveViewKey(m_keys.spend_secret_key);

    // Derive public keys
    m_keys.spend_public_key = DerivePublicKey(m_keys.spend_secret_key);
    m_keys.view_public_key = DerivePublicKey(m_keys.view_secret_key);

    m_initialized = true;

    LogPrintf("MoneroWallet: Initialized from WATTx seed\n");
    LogPrintf("MoneroWallet: Primary address: %s\n", GetPrimaryAddress().address);

    return true;
}

bool MoneroLightWallet::InitFromKeys(const MoneroSecretKey& spend_key, const MoneroSecretKey& view_key,
                                      MoneroNetworkType network) {
    m_network = network;
    m_keys.spend_secret_key = spend_key;
    m_keys.view_secret_key = view_key;
    m_keys.spend_public_key = DerivePublicKey(spend_key);
    m_keys.view_public_key = DerivePublicKey(view_key);

    m_initialized = true;

    LogPrintf("MoneroWallet: Initialized from keys\n");
    LogPrintf("MoneroWallet: Primary address: %s\n", GetPrimaryAddress().address);

    return true;
}

MoneroAddress MoneroLightWallet::GetPrimaryAddress() const {
    MoneroAddress addr;
    addr.network = m_network;
    addr.is_subaddress = false;
    addr.major_index = 0;
    addr.minor_index = 0;

    if (!m_initialized) {
        return addr;
    }

    addr.address = EncodeAddress(m_keys.spend_public_key, m_keys.view_public_key,
                                  m_network, false);
    return addr;
}

MoneroAddress MoneroLightWallet::GetSubaddress(uint32_t account, uint32_t index) const {
    MoneroAddress addr;
    addr.network = m_network;
    addr.is_subaddress = true;
    addr.major_index = account;
    addr.minor_index = index;

    if (!m_initialized) {
        return addr;
    }

    // For account 0, index 0, return primary address
    if (account == 0 && index == 0) {
        return GetPrimaryAddress();
    }

    auto [spend_pub, view_pub] = DeriveSubaddressKeys(account, index);
    addr.address = EncodeAddress(spend_pub, view_pub, m_network, true);

    return addr;
}

std::string MoneroLightWallet::ExportViewKey() const {
    if (!m_initialized) return "";
    return HexStr(m_keys.view_secret_key);
}

void MoneroLightWallet::SetDaemonConnection(const std::string& host, uint16_t port) {
    m_daemon_host = host;
    m_daemon_port = port;
}

bool MoneroLightWallet::QueryBalance(MoneroBalance& balance) {
    if (!m_initialized || m_daemon_host.empty()) {
        return false;
    }

    // Query daemon for balance
    // This uses the get_balance RPC call
    std::string params = "{\"account_index\":0}";
    std::string response = DaemonRPC("get_balance", params);

    if (response.empty()) {
        return false;
    }

    // Parse balance from response (simplified parsing)
    // In production, use proper JSON parser
    size_t pos = response.find("\"balance\":");
    if (pos != std::string::npos) {
        pos += 10;
        size_t end = response.find_first_of(",}", pos);
        if (end != std::string::npos) {
            std::string bal_str = response.substr(pos, end - pos);
            balance.balance = std::stoull(bal_str);
        }
    }

    pos = response.find("\"unlocked_balance\":");
    if (pos != std::string::npos) {
        pos += 19;
        size_t end = response.find_first_of(",}", pos);
        if (end != std::string::npos) {
            std::string bal_str = response.substr(pos, end - pos);
            balance.unlocked_balance = std::stoull(bal_str);
        }
    }

    return true;
}

std::string MoneroLightWallet::GetMnemonicSeed() const {
    // Monero uses a 25-word mnemonic (Electrum-style)
    // This is a simplified version - full implementation needs the wordlist
    if (!m_initialized) return "";

    // For now, just return the hex of the spend key
    // Full implementation would convert to mnemonic words
    return "seed:" + HexStr(m_keys.spend_secret_key);
}

bool MoneroLightWallet::IsOurAddress(const std::string& address) const {
    if (!m_initialized) return false;

    MoneroPublicKey spend_pub, view_pub;
    MoneroNetworkType network;
    bool is_subaddress;

    if (!DecodeAddress(address, spend_pub, view_pub, network, is_subaddress)) {
        return false;
    }

    // For primary address, direct comparison
    if (!is_subaddress) {
        return spend_pub == m_keys.spend_public_key &&
               view_pub == m_keys.view_public_key;
    }

    // For subaddresses, we'd need to try deriving subaddresses
    // This is expensive, so we limit the search range
    for (uint32_t account = 0; account < 10; account++) {
        for (uint32_t index = 0; index < 100; index++) {
            auto [sub_spend, sub_view] = DeriveSubaddressKeys(account, index);
            if (spend_pub == sub_spend && view_pub == sub_view) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// Private Methods
// ============================================================================

MoneroPublicKey MoneroLightWallet::DerivePublicKey(const MoneroSecretKey& secret) {
    MoneroPublicKey pub;
    ed25519::derive_public_key(secret.data(), pub.data());
    return pub;
}

MoneroSecretKey MoneroLightWallet::DeriveViewKey(const MoneroSecretKey& spend_key) {
    MoneroSecretKey view_key;

    // Monero derives view key as: view = H_s(spend_key)
    // where H_s is keccak-256 reduced mod l
    auto hash = Keccak256(spend_key.data(), 32);
    std::memcpy(view_key.data(), hash.data(), 32);
    ScalarReduce(view_key);

    return view_key;
}

std::pair<MoneroPublicKey, MoneroPublicKey> MoneroLightWallet::DeriveSubaddressKeys(
    uint32_t account, uint32_t index) const {

    MoneroPublicKey spend_pub, view_pub;

    // Subaddress derivation:
    // m = H_s("SubAddr" || view_secret || account || index)
    // D = B + m*G (new spend public)
    // C = a*D (new view public, a is view secret)

    std::vector<uint8_t> data;
    data.insert(data.end(), {'S', 'u', 'b', 'A', 'd', 'd', 'r', 0});
    data.insert(data.end(), m_keys.view_secret_key.begin(), m_keys.view_secret_key.end());

    // Add account and index (little-endian)
    for (int i = 0; i < 4; i++) {
        data.push_back((account >> (i * 8)) & 0xFF);
    }
    for (int i = 0; i < 4; i++) {
        data.push_back((index >> (i * 8)) & 0xFF);
    }

    auto m = Keccak256(data.data(), data.size());

    // Simplified: just hash to get deterministic subaddress keys
    // Real implementation needs proper elliptic curve operations
    CSHA256 hasher;
    hasher.Write(m.data(), 32);
    hasher.Write(m_keys.spend_public_key.data(), 32);
    hasher.Finalize(spend_pub.data());

    hasher.Reset();
    hasher.Write(m.data(), 32);
    hasher.Write(m_keys.view_public_key.data(), 32);
    hasher.Finalize(view_pub.data());

    return {spend_pub, view_pub};
}

std::string MoneroLightWallet::EncodeAddress(const MoneroPublicKey& spend_pub,
                                              const MoneroPublicKey& view_pub,
                                              MoneroNetworkType network,
                                              bool is_subaddress) {
    std::vector<uint8_t> data;

    // Network prefix
    uint8_t prefix;
    switch (network) {
        case MoneroNetworkType::MAINNET:
            prefix = is_subaddress ? MAINNET_PUBLIC_SUBADDRESS_PREFIX : MAINNET_PUBLIC_ADDRESS_PREFIX;
            break;
        case MoneroNetworkType::TESTNET:
            prefix = is_subaddress ? TESTNET_PUBLIC_SUBADDRESS_PREFIX : TESTNET_PUBLIC_ADDRESS_PREFIX;
            break;
        case MoneroNetworkType::STAGENET:
            prefix = is_subaddress ? STAGENET_PUBLIC_SUBADDRESS_PREFIX : STAGENET_PUBLIC_ADDRESS_PREFIX;
            break;
    }

    data.push_back(prefix);
    data.insert(data.end(), spend_pub.begin(), spend_pub.end());
    data.insert(data.end(), view_pub.begin(), view_pub.end());

    return base58::EncodeCheck(data);
}

bool MoneroLightWallet::DecodeAddress(const std::string& address,
                                       MoneroPublicKey& spend_pub,
                                       MoneroPublicKey& view_pub,
                                       MoneroNetworkType& network,
                                       bool& is_subaddress) {
    std::vector<uint8_t> data;
    if (!base58::DecodeCheck(address, data)) {
        return false;
    }

    if (data.size() != 65) {  // 1 prefix + 32 spend + 32 view
        return false;
    }

    uint8_t prefix = data[0];

    if (prefix == MAINNET_PUBLIC_ADDRESS_PREFIX) {
        network = MoneroNetworkType::MAINNET;
        is_subaddress = false;
    } else if (prefix == MAINNET_PUBLIC_SUBADDRESS_PREFIX) {
        network = MoneroNetworkType::MAINNET;
        is_subaddress = true;
    } else if (prefix == TESTNET_PUBLIC_ADDRESS_PREFIX) {
        network = MoneroNetworkType::TESTNET;
        is_subaddress = false;
    } else if (prefix == TESTNET_PUBLIC_SUBADDRESS_PREFIX) {
        network = MoneroNetworkType::TESTNET;
        is_subaddress = true;
    } else if (prefix == STAGENET_PUBLIC_ADDRESS_PREFIX) {
        network = MoneroNetworkType::STAGENET;
        is_subaddress = false;
    } else if (prefix == STAGENET_PUBLIC_SUBADDRESS_PREFIX) {
        network = MoneroNetworkType::STAGENET;
        is_subaddress = true;
    } else {
        return false;
    }

    std::memcpy(spend_pub.data(), data.data() + 1, 32);
    std::memcpy(view_pub.data(), data.data() + 33, 32);

    return true;
}

std::array<uint8_t, 32> MoneroLightWallet::Keccak256(const void* data, size_t len) {
    std::array<uint8_t, 32> hash;

    // Use the keccak function if available, otherwise fall back to SHA256
    // In production, must use actual Keccak-256 (not SHA3-256!)
#ifdef HAVE_KECCAK
    keccak((const uint8_t*)data, len, hash.data(), 32);
#else
    // Fallback: use SHA256 (not cryptographically equivalent, but functional for testing)
    CSHA256 hasher;
    hasher.Write((const uint8_t*)data, len);
    hasher.Finalize(hash.data());
#endif

    return hash;
}

void MoneroLightWallet::ScalarReduce(MoneroSecretKey& key) {
    ed25519::sc_reduce32(key.data());
}

std::string MoneroLightWallet::DaemonRPC(const std::string& method, const std::string& params) {
#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return "";
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) { WSACleanup(); return ""; }

    DWORD timeout_ms = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_daemon_port);

    struct hostent* he = gethostbyname(m_daemon_host.c_str());
    if (!he) {
#ifdef WIN32
        closesocket(sock); WSACleanup();
#else
        close(sock);
#endif
        return "";
    }
    std::memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
#ifdef WIN32
        closesocket(sock); WSACleanup();
#else
        close(sock);
#endif
        return "";
    }

    // Build JSON-RPC request
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"" << method << "\"";
    if (!params.empty()) {
        body << ",\"params\":" << params;
    }
    body << "}";
    std::string body_str = body.str();

    std::ostringstream request;
    request << "POST /json_rpc HTTP/1.1\r\n";
    request << "Host: " << m_daemon_host << ":" << m_daemon_port << "\r\n";
    request << "Content-Type: application/json\r\n";
    request << "Content-Length: " << body_str.length() << "\r\n";
    request << "Connection: close\r\n\r\n";
    request << body_str;

    std::string req_str = request.str();
    if (send(sock, req_str.c_str(), req_str.length(), 0) < 0) {
#ifdef WIN32
        closesocket(sock); WSACleanup();
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
    WSACleanup();
#else
    close(sock);
#endif

    // Extract body
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

// ============================================================================
// Base58 Implementation
// ============================================================================

namespace base58 {

static const char ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t ALPHABET_MAP[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

// Monero uses 8-byte blocks encoded to 11 characters
static const size_t FULL_BLOCK_SIZE = 8;
static const size_t FULL_ENCODED_BLOCK_SIZE = 11;

static const size_t ENCODED_BLOCK_SIZES[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};

std::string EncodeBlock(const uint8_t* data, size_t size) {
    if (size > FULL_BLOCK_SIZE) return "";

    // Convert to big integer
    uint64_t num = 0;
    for (size_t i = 0; i < size; i++) {
        num = num * 256 + data[i];
    }

    size_t encoded_size = ENCODED_BLOCK_SIZES[size];
    std::string result(encoded_size, ALPHABET[0]);

    for (size_t i = encoded_size; i > 0; i--) {
        result[i - 1] = ALPHABET[num % 58];
        num /= 58;
    }

    return result;
}

bool DecodeBlock(const std::string& encoded, std::vector<uint8_t>& data) {
    size_t encoded_size = encoded.size();

    // Find the decoded size
    size_t decoded_size = 0;
    for (size_t i = 0; i <= FULL_BLOCK_SIZE; i++) {
        if (ENCODED_BLOCK_SIZES[i] == encoded_size) {
            decoded_size = i;
            break;
        }
    }
    if (decoded_size == 0 && encoded_size != 0) return false;

    // Convert from base58
    uint64_t num = 0;
    for (char c : encoded) {
        if (c < 0 || c >= 128) return false;
        int8_t val = ALPHABET_MAP[(int)c];
        if (val < 0) return false;
        num = num * 58 + val;
    }

    // Convert to bytes
    for (size_t i = decoded_size; i > 0; i--) {
        data.push_back(num & 0xFF);
        num >>= 8;
    }

    std::reverse(data.end() - decoded_size, data.end());
    return true;
}

std::string Encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    std::string result;
    size_t full_blocks = data.size() / FULL_BLOCK_SIZE;
    size_t last_block_size = data.size() % FULL_BLOCK_SIZE;

    for (size_t i = 0; i < full_blocks; i++) {
        result += EncodeBlock(data.data() + i * FULL_BLOCK_SIZE, FULL_BLOCK_SIZE);
    }

    if (last_block_size > 0) {
        result += EncodeBlock(data.data() + full_blocks * FULL_BLOCK_SIZE, last_block_size);
    }

    return result;
}

bool Decode(const std::string& encoded, std::vector<uint8_t>& data) {
    if (encoded.empty()) return true;

    data.clear();

    size_t full_blocks = encoded.size() / FULL_ENCODED_BLOCK_SIZE;
    size_t last_block_size = encoded.size() % FULL_ENCODED_BLOCK_SIZE;

    for (size_t i = 0; i < full_blocks; i++) {
        if (!DecodeBlock(encoded.substr(i * FULL_ENCODED_BLOCK_SIZE, FULL_ENCODED_BLOCK_SIZE), data)) {
            return false;
        }
    }

    if (last_block_size > 0) {
        if (!DecodeBlock(encoded.substr(full_blocks * FULL_ENCODED_BLOCK_SIZE), data)) {
            return false;
        }
    }

    return true;
}

std::string EncodeCheck(const std::vector<uint8_t>& data) {
    // Monero uses 4-byte checksum from keccak
    std::vector<uint8_t> with_check = data;

    std::array<uint8_t, 32> hash;
    CSHA256 hasher;
    hasher.Write(data.data(), data.size());
    hasher.Finalize(hash.data());

    // Append first 4 bytes of hash as checksum
    with_check.insert(with_check.end(), hash.begin(), hash.begin() + 4);

    return Encode(with_check);
}

bool DecodeCheck(const std::string& encoded, std::vector<uint8_t>& data) {
    std::vector<uint8_t> decoded;
    if (!Decode(encoded, decoded)) {
        return false;
    }

    if (decoded.size() < 4) {
        return false;
    }

    // Verify checksum
    std::vector<uint8_t> payload(decoded.begin(), decoded.end() - 4);
    std::vector<uint8_t> checksum(decoded.end() - 4, decoded.end());

    std::array<uint8_t, 32> hash;
    CSHA256 hasher;
    hasher.Write(payload.data(), payload.size());
    hasher.Finalize(hash.data());

    if (std::memcmp(hash.data(), checksum.data(), 4) != 0) {
        return false;
    }

    data = payload;
    return true;
}

}  // namespace base58

}  // namespace monero_wallet
