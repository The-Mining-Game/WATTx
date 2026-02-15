// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bridge/bridge_node.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <random.h>
#include <span.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <sstream>

namespace bridge {

// ============================================================================
// Global Instance
// ============================================================================

static BridgeNode g_bridge_node;

BridgeNode& GetBridgeNode() {
    return g_bridge_node;
}

// ============================================================================
// BridgeNode Implementation
// ============================================================================

BridgeNode::BridgeNode() = default;

BridgeNode::~BridgeNode() {
    Stop();
}

bool BridgeNode::Start(const BridgeConfig& config) {
    if (m_running.load()) {
        LogPrintf("BridgeNode: Already running\n");
        return false;
    }

    m_config = config;
    m_running.store(true);

    // Initialize current batch
    m_current_batch.batch_id = 0;
    m_current_batch.created_at = GetTime();

    // Start worker threads
    m_wattx_monitor_thread = std::thread(&BridgeNode::WattxMonitorThread, this);
    m_monero_monitor_thread = std::thread(&BridgeNode::MoneroMonitorThread, this);
    m_batch_processor_thread = std::thread(&BridgeNode::BatchProcessorThread, this);
    m_swap_monitor_thread = std::thread(&BridgeNode::SwapMonitorThread, this);

    LogPrintf("BridgeNode: Started\n");
    LogPrintf("BridgeNode: WATTx RPC: %s:%d\n", m_config.wattx_rpc_host, m_config.wattx_rpc_port);
    LogPrintf("BridgeNode: Monero daemon: %s:%d\n", m_config.monero_daemon_host, m_config.monero_daemon_port);
    LogPrintf("BridgeNode: Validator mode: %s\n", m_config.is_validator ? "enabled" : "disabled");

    return true;
}

void BridgeNode::Stop() {
    if (!m_running.load()) return;

    LogPrintf("BridgeNode: Stopping...\n");
    m_running.store(false);

    // Wake up any waiting threads
    m_cv.notify_all();

    // Join all threads
    if (m_wattx_monitor_thread.joinable()) m_wattx_monitor_thread.join();
    if (m_monero_monitor_thread.joinable()) m_monero_monitor_thread.join();
    if (m_batch_processor_thread.joinable()) m_batch_processor_thread.join();
    if (m_swap_monitor_thread.joinable()) m_swap_monitor_thread.join();

    LogPrintf("BridgeNode: Stopped\n");
}

// ============================================================================
// Transaction Management
// ============================================================================

uint256 BridgeNode::SubmitTransaction(const std::string& from_chain,
                                       const std::string& to_chain,
                                       uint64_t amount,
                                       const std::string& destination) {
    // Generate transaction hash
    CSHA256 hasher;
    hasher.Write((const uint8_t*)from_chain.data(), from_chain.size());
    hasher.Write((const uint8_t*)to_chain.data(), to_chain.size());
    hasher.Write((const uint8_t*)&amount, sizeof(amount));
    hasher.Write((const uint8_t*)destination.data(), destination.size());
    int64_t now = GetTime();
    hasher.Write((const uint8_t*)&now, sizeof(now));

    uint256 tx_hash;
    hasher.Finalize(tx_hash.data());

    PendingTransaction tx;
    tx.tx_hash = tx_hash;
    tx.from_chain = from_chain;
    tx.to_chain = to_chain;
    tx.amount = amount;
    tx.destination = destination;
    tx.created_at = now;
    tx.confirmed_at = 0;
    tx.confirmations = 0;
    tx.completed = false;
    tx.refunded = false;

    {
        std::lock_guard<std::mutex> lock(m_tx_mutex);
        m_pending_txs[tx_hash] = tx;
    }

    // Add to current batch
    {
        std::lock_guard<std::mutex> lock(m_batch_mutex);
        m_current_batch.tx_hashes.push_back(tx_hash);
    }

    m_total_transactions++;

    LogPrintf("BridgeNode: Submitted transaction %s (%s -> %s, %lu)\n",
              tx_hash.GetHex().substr(0, 16), from_chain, to_chain, amount);

    return tx_hash;
}

PendingTransaction BridgeNode::GetTransaction(const uint256& tx_hash) {
    std::lock_guard<std::mutex> lock(m_tx_mutex);
    auto it = m_pending_txs.find(tx_hash);
    if (it != m_pending_txs.end()) {
        return it->second;
    }
    return PendingTransaction{};
}

std::vector<PendingTransaction> BridgeNode::GetPendingTransactions() {
    std::lock_guard<std::mutex> lock(m_tx_mutex);
    std::vector<PendingTransaction> result;
    for (const auto& [hash, tx] : m_pending_txs) {
        if (!tx.completed && !tx.refunded) {
            result.push_back(tx);
        }
    }
    return result;
}

uint64_t BridgeNode::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(m_tx_mutex);
    uint64_t count = 0;
    for (const auto& [hash, tx] : m_pending_txs) {
        if (!tx.completed && !tx.refunded) {
            count++;
        }
    }
    return count;
}

// ============================================================================
// Atomic Swap Management
// ============================================================================

uint256 BridgeNode::InitiateSwap(uint64_t wtx_amount, const std::string& xmr_destination) {
    // Generate random preimage (secret)
    uint256 preimage;
    GetRandBytes(Span{preimage.data(), 32});

    // Calculate hash lock
    uint256 hash_lock;
    CSHA256 hasher;
    hasher.Write(preimage.data(), 32);
    hasher.Finalize(hash_lock.data());

    // Generate swap ID
    uint256 swap_id;
    hasher.Reset();
    hasher.Write(hash_lock.data(), 32);
    int64_t now = GetTime();
    hasher.Write((const uint8_t*)&now, sizeof(now));
    hasher.Finalize(swap_id.data());

    AtomicSwap swap;
    swap.swap_id = swap_id;
    swap.initiator = "self";  // Would be actual address
    swap.participant = xmr_destination;
    swap.amount = wtx_amount;
    swap.hash_lock = hash_lock;
    swap.preimage = preimage;
    swap.timelock = now + 3600;  // 1 hour timeout
    swap.state = "active";
    swap.wattx_side_complete = false;
    swap.monero_side_complete = false;

    {
        std::lock_guard<std::mutex> lock(m_swap_mutex);
        m_swaps[swap_id] = swap;
    }

    // Create HTLC on WATTx chain
    if (!CreateWattxHTLC(swap)) {
        LogPrintf("BridgeNode: Failed to create WATTx HTLC for swap %s\n",
                  swap_id.GetHex().substr(0, 16));
        return uint256{};
    }

    m_total_swaps++;

    LogPrintf("BridgeNode: Initiated swap %s (WTX: %lu -> XMR: %s)\n",
              swap_id.GetHex().substr(0, 16), wtx_amount, xmr_destination.substr(0, 16));

    return swap_id;
}

bool BridgeNode::ParticipateSwap(const uint256& swap_id, uint64_t xmr_amount) {
    std::lock_guard<std::mutex> lock(m_swap_mutex);
    auto it = m_swaps.find(swap_id);
    if (it == m_swaps.end()) {
        LogPrintf("BridgeNode: Swap %s not found\n", swap_id.GetHex().substr(0, 16));
        return false;
    }

    AtomicSwap& swap = it->second;
    if (swap.state != "active") {
        LogPrintf("BridgeNode: Swap %s not active\n", swap_id.GetHex().substr(0, 16));
        return false;
    }

    // Create Monero HTLC
    if (!CreateMoneroHTLC(swap)) {
        LogPrintf("BridgeNode: Failed to create Monero HTLC for swap %s\n",
                  swap_id.GetHex().substr(0, 16));
        return false;
    }

    LogPrintf("BridgeNode: Participated in swap %s (XMR: %lu)\n",
              swap_id.GetHex().substr(0, 16), xmr_amount);

    return true;
}

bool BridgeNode::ClaimSwap(const uint256& swap_id, const uint256& preimage) {
    std::lock_guard<std::mutex> lock(m_swap_mutex);
    auto it = m_swaps.find(swap_id);
    if (it == m_swaps.end()) {
        return false;
    }

    AtomicSwap& swap = it->second;
    if (swap.state != "active") {
        return false;
    }

    // Verify preimage
    uint256 hash_lock;
    CSHA256 hasher;
    hasher.Write(preimage.data(), 32);
    hasher.Finalize(hash_lock.data());

    if (hash_lock != swap.hash_lock) {
        LogPrintf("BridgeNode: Invalid preimage for swap %s\n",
                  swap_id.GetHex().substr(0, 16));
        return false;
    }

    swap.preimage = preimage;
    swap.state = "claimed";

    // Call claim on both chains' contracts
    // ... (would interact with contracts via RPC)

    LogPrintf("BridgeNode: Claimed swap %s\n", swap_id.GetHex().substr(0, 16));

    return true;
}

bool BridgeNode::RefundSwap(const uint256& swap_id) {
    std::lock_guard<std::mutex> lock(m_swap_mutex);
    auto it = m_swaps.find(swap_id);
    if (it == m_swaps.end()) {
        return false;
    }

    AtomicSwap& swap = it->second;
    if (swap.state != "active") {
        return false;
    }

    if (GetTime() < swap.timelock) {
        LogPrintf("BridgeNode: Swap %s not yet expired\n", swap_id.GetHex().substr(0, 16));
        return false;
    }

    swap.state = "refunded";

    // Call refund on contracts
    // ... (would interact with contracts via RPC)

    LogPrintf("BridgeNode: Refunded swap %s\n", swap_id.GetHex().substr(0, 16));

    return true;
}

AtomicSwap BridgeNode::GetSwap(const uint256& swap_id) {
    std::lock_guard<std::mutex> lock(m_swap_mutex);
    auto it = m_swaps.find(swap_id);
    if (it != m_swaps.end()) {
        return it->second;
    }
    return AtomicSwap{};
}

// ============================================================================
// Batch Management
// ============================================================================

TransactionBatch BridgeNode::GetCurrentBatch() {
    std::lock_guard<std::mutex> lock(m_batch_mutex);
    return m_current_batch;
}

bool BridgeNode::CommitBatch() {
    if (!m_config.is_validator) {
        LogPrintf("BridgeNode: Only validators can commit batches\n");
        return false;
    }

    std::lock_guard<std::mutex> lock(m_batch_mutex);

    if (m_current_batch.tx_hashes.empty()) {
        LogPrintf("BridgeNode: Empty batch, nothing to commit\n");
        return false;
    }

    CreateBatch();
    return true;
}

void BridgeNode::CreateBatch() {
    // Calculate merkle root
    m_current_batch.merkle_root = ComputeMerkleRoot(m_current_batch.tx_hashes);
    m_current_batch.committed_at = GetTime();

    // Submit to WATTx contract
    SubmitBatchToWattx();

    // Store in committed batches
    m_committed_batches.push_back(m_current_batch);

    LogPrintf("BridgeNode: Committed batch %lu with %zu transactions, merkle root: %s\n",
              m_current_batch.batch_id,
              m_current_batch.tx_hashes.size(),
              m_current_batch.merkle_root.GetHex().substr(0, 16));

    // Start new batch
    m_current_batch = TransactionBatch{};
    m_current_batch.batch_id = m_committed_batches.back().batch_id + 1;
    m_current_batch.created_at = GetTime();
}

uint256 BridgeNode::ComputeMerkleRoot(const std::vector<uint256>& hashes) {
    if (hashes.empty()) return uint256{};
    if (hashes.size() == 1) return hashes[0];

    std::vector<uint256> nodes = hashes;

    while (nodes.size() > 1) {
        std::vector<uint256> new_nodes;
        for (size_t i = 0; i < nodes.size(); i += 2) {
            uint256 combined;
            if (i + 1 < nodes.size()) {
                combined = Hash(nodes[i], nodes[i + 1]);
            } else {
                combined = Hash(nodes[i], nodes[i]);
            }
            new_nodes.push_back(combined);
        }
        nodes = new_nodes;
    }

    return nodes[0];
}

void BridgeNode::SubmitBatchToWattx() {
    if (m_config.bridge_contract_address.empty()) {
        LogPrintf("BridgeNode: No bridge contract configured\n");
        return;
    }

    // Call commitBatch on the PrivacyBridge contract
    // This would use WATTx RPC to send a transaction
    std::ostringstream params;
    params << "{\"to\":\"" << m_config.bridge_contract_address << "\",";
    params << "\"data\":\"0x" << m_current_batch.merkle_root.GetHex() << "\"}";

    std::string result = WattxRPC("eth_sendTransaction", params.str());

    if (!result.empty()) {
        m_current_batch.committed_to_wattx = true;
        LogPrintf("BridgeNode: Batch submitted to WATTx contract\n");
    }
}

void BridgeNode::ConfirmBatchOnMonero() {
    // Query Monero for recent blocks containing our commitment
    // This would look for the merge mining tag in Monero blocks

    std::string result = MoneroRPC("get_last_block_header", "{}");

    if (!result.empty()) {
        // Parse block height and hash from response
        // Check if our commitment is in the coinbase extra field
        // If found, mark batch as confirmed

        // For now, just log
        LogPrintf("BridgeNode: Checking Monero for batch confirmations\n");
    }
}

// ============================================================================
// Worker Threads
// ============================================================================

void BridgeNode::WattxMonitorThread() {
    LogPrintf("BridgeNode: WATTx monitor thread started\n");

    while (m_running.load()) {
        // Get current block height
        std::string result = WattxRPC("getblockcount", "[]");

        if (!result.empty()) {
            // Parse height from result
            // For simplicity, assume JSON parsing here
            uint64_t height = 0;
            size_t pos = result.find("result");
            if (pos != std::string::npos) {
                pos = result.find(":", pos);
                if (pos != std::string::npos) {
                    height = std::stoull(result.substr(pos + 1));
                }
            }

            if (height > m_wattx_height) {
                for (uint64_t h = m_wattx_height + 1; h <= height; h++) {
                    ProcessWattxBlock(h);
                }
                m_wattx_height = height;
            }
        }

        // Sleep for 10 seconds
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    LogPrintf("BridgeNode: WATTx monitor thread stopped\n");
}

void BridgeNode::MoneroMonitorThread() {
    LogPrintf("BridgeNode: Monero monitor thread started\n");

    while (m_running.load()) {
        // Get current block height
        std::string result = MoneroRPC("get_block_count", "{}");

        if (!result.empty()) {
            // Parse height from result
            uint64_t height = 0;
            size_t pos = result.find("\"count\"");
            if (pos != std::string::npos) {
                pos = result.find(":", pos);
                if (pos != std::string::npos) {
                    height = std::stoull(result.substr(pos + 1));
                }
            }

            if (height > m_monero_height) {
                for (uint64_t h = m_monero_height + 1; h <= height; h++) {
                    ProcessMoneroBlock(h);
                }
                m_monero_height = height;
            }
        }

        // Sleep for 30 seconds (Monero has ~2 min blocks)
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    LogPrintf("BridgeNode: Monero monitor thread stopped\n");
}

void BridgeNode::BatchProcessorThread() {
    LogPrintf("BridgeNode: Batch processor thread started\n");

    while (m_running.load()) {
        // Check if batch interval has passed
        {
            std::lock_guard<std::mutex> lock(m_batch_mutex);
            int64_t now = GetTime();

            if (m_config.is_validator &&
                !m_current_batch.tx_hashes.empty() &&
                now - m_current_batch.created_at >= m_config.batch_interval) {

                CreateBatch();
            }
        }

        // Update confirmations for pending batches
        ConfirmBatchOnMonero();

        // Sleep for batch interval
        std::unique_lock<std::mutex> lock(m_cv_mutex);
        m_cv.wait_for(lock, std::chrono::seconds(60));
    }

    LogPrintf("BridgeNode: Batch processor thread stopped\n");
}

void BridgeNode::SwapMonitorThread() {
    LogPrintf("BridgeNode: Swap monitor thread started\n");

    while (m_running.load()) {
        MonitorSwapTimeouts();

        // Sleep for 30 seconds
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    LogPrintf("BridgeNode: Swap monitor thread stopped\n");
}

void BridgeNode::ProcessWattxBlock(uint64_t height) {
    // Get block at height and process relevant transactions
    // Look for:
    // - Bridge contract events
    // - Atomic swap contract events

    std::ostringstream params;
    params << "[" << height << "]";
    std::string result = WattxRPC("getblockhash", params.str());

    // Process transactions...
    LogPrintf("BridgeNode: Processed WATTx block %lu\n", height);
}

void BridgeNode::ProcessMoneroBlock(uint64_t height) {
    // Get block at height and look for merge mining tags
    // This confirms batches that were committed via merged mining

    std::ostringstream params;
    params << "{\"height\":" << height << "}";
    std::string result = MoneroRPC("get_block_header_by_height", params.str());

    // Process block...
    LogPrintf("BridgeNode: Processed Monero block %lu\n", height);
}

void BridgeNode::UpdateTransactionConfirmations() {
    std::lock_guard<std::mutex> lock(m_tx_mutex);

    for (auto& [hash, tx] : m_pending_txs) {
        if (tx.completed || tx.refunded) continue;

        // Update confirmations based on chain
        // Mark as completed if enough confirmations
        if (tx.confirmations >= m_config.confirmation_threshold) {
            tx.completed = true;
            LogPrintf("BridgeNode: Transaction %s completed with %d confirmations\n",
                      hash.GetHex().substr(0, 16), tx.confirmations);
        }
    }
}

void BridgeNode::MonitorSwapTimeouts() {
    std::lock_guard<std::mutex> lock(m_swap_mutex);
    int64_t now = GetTime();

    for (auto& [id, swap] : m_swaps) {
        if (swap.state == "active" && now >= swap.timelock) {
            LogPrintf("BridgeNode: Swap %s timed out\n", id.GetHex().substr(0, 16));
            // Would trigger refund process
        }
    }
}

bool BridgeNode::CreateWattxHTLC(const AtomicSwap& swap) {
    if (m_config.atomic_swap_address.empty()) {
        return false;
    }

    // Call createSwap on AtomicSwap contract
    // ... (implementation would interact with contract)

    return true;
}

bool BridgeNode::CreateMoneroHTLC(const AtomicSwap& swap) {
    // Monero doesn't have smart contracts, so this would:
    // 1. Create a view-only wallet address for the swap
    // 2. Use multisig or adaptor signatures for atomic swap

    return true;
}

// ============================================================================
// RPC Communication
// ============================================================================

std::string BridgeNode::WattxRPC(const std::string& method, const std::string& params) {
    std::ostringstream body;
    body << "{\"jsonrpc\":\"1.0\",\"id\":\"bridge\",\"method\":\"" << method << "\",";
    body << "\"params\":" << params << "}";

    std::string auth = m_config.wattx_rpc_user + ":" + m_config.wattx_rpc_pass;
    return HttpPost(m_config.wattx_rpc_host, m_config.wattx_rpc_port, "/", body.str(), auth);
}

std::string BridgeNode::MoneroRPC(const std::string& method, const std::string& params) {
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"" << method << "\"";
    if (!params.empty() && params != "{}") {
        body << ",\"params\":" << params;
    }
    body << "}";

    return HttpPost(m_config.monero_daemon_host, m_config.monero_daemon_port,
                    "/json_rpc", body.str());
}

std::string BridgeNode::MoneroWalletRPC(const std::string& method, const std::string& params) {
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"" << method << "\"";
    if (!params.empty() && params != "{}") {
        body << ",\"params\":" << params;
    }
    body << "}";

    return HttpPost(m_config.monero_wallet_host, m_config.monero_wallet_port,
                    "/json_rpc", body.str());
}

std::string BridgeNode::HttpPost(const std::string& host, uint16_t port,
                                  const std::string& path, const std::string& body,
                                  const std::string& auth) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    // Set timeout
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
    addr.sin_port = htons(port);

    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
        close(sock);
        return "";
    }
    std::memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    std::ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << ":" << port << "\r\n";
    request << "Content-Type: application/json\r\n";
    request << "Content-Length: " << body.length() << "\r\n";

    if (!auth.empty()) {
        // Base64 encode auth
        static const char* base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        int val = 0, valb = -6;
        for (unsigned char c : auth) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (encoded.size() % 4) encoded.push_back('=');

        request << "Authorization: Basic " << encoded << "\r\n";
    }

    request << "Connection: close\r\n\r\n";
    request << body;

    std::string req_str = request.str();
    if (send(sock, req_str.c_str(), req_str.length(), 0) < 0) {
        close(sock);
        return "";
    }

    std::string response;
    char buffer[4096];
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
    }

    close(sock);

    // Extract body
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

}  // namespace bridge
