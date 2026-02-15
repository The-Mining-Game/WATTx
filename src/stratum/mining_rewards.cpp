// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stratum/mining_rewards.h>
#include <logging.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
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

namespace mining_rewards {

// ============================================================================
// Global Instance
// ============================================================================

static MiningRewardsManager g_mining_rewards_manager;

MiningRewardsManager& GetMiningRewardsManager() {
    return g_mining_rewards_manager;
}

// ============================================================================
// Contract Function Selectors (keccak256 of function signature, first 4 bytes)
// ============================================================================

// submitShares(address,uint256,bool,bool,uint256,uint256)
static const std::string SUBMIT_SHARES_SELECTOR = "0x8e7ea5b2";

// finalizeBlock()
static const std::string FINALIZE_BLOCK_SELECTOR = "0x4bb278f3";

// ============================================================================
// MiningRewardsManager Implementation
// ============================================================================

MiningRewardsManager::MiningRewardsManager() = default;

MiningRewardsManager::~MiningRewardsManager() {
    Stop();
}

bool MiningRewardsManager::Initialize(const MiningRewardsConfig& config) {
    if (m_initialized.load()) {
        LogPrintf("MiningRewards: Already initialized\n");
        return true;
    }

    if (!config.enabled) {
        LogPrintf("MiningRewards: Disabled in config\n");
        return true;
    }

    if (config.contract_address.empty()) {
        LogPrintf("MiningRewards: No contract address configured\n");
        return false;
    }

    m_config = config;
    m_initialized.store(true);

    LogPrintf("MiningRewards: Initialized\n");
    LogPrintf("MiningRewards: Contract: %s\n", m_config.contract_address);
    LogPrintf("MiningRewards: RPC: %s:%d\n", m_config.wattx_rpc_host, m_config.wattx_rpc_port);
    LogPrintf("MiningRewards: Batch interval: %d seconds\n", m_config.batch_interval_seconds);

    return true;
}

bool MiningRewardsManager::Start() {
    if (!m_initialized.load() || !m_config.enabled) {
        return false;
    }

    if (m_running.load()) {
        return true;
    }

    m_running.store(true);
    m_submission_thread = std::thread(&MiningRewardsManager::SubmissionThread, this);

    LogPrintf("MiningRewards: Started submission thread\n");
    return true;
}

void MiningRewardsManager::Stop() {
    if (!m_running.load()) {
        return;
    }

    LogPrintf("MiningRewards: Stopping...\n");
    m_running.store(false);

    // Wake up thread
    m_cv.notify_all();
    m_block_cv.notify_all();

    if (m_submission_thread.joinable()) {
        m_submission_thread.join();
    }

    LogPrintf("MiningRewards: Stopped\n");
}

void MiningRewardsManager::QueueShare(const ShareSubmission& share) {
    if (!m_running.load()) return;

    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_share_queue.push(share);
    }

    // Wake up thread if batch size reached
    if (GetPendingShareCount() >= static_cast<size_t>(m_config.max_batch_size)) {
        m_cv.notify_one();
    }
}

void MiningRewardsManager::FlushPendingShares() {
    m_cv.notify_one();
}

void MiningRewardsManager::NotifyBlockFound(uint64_t moneroHeight, uint64_t wattxHeight) {
    {
        std::lock_guard<std::mutex> lock(m_block_mutex);
        m_block_found = true;
        m_last_monero_height = moneroHeight;
        m_last_wattx_height = wattxHeight;
    }

    m_block_cv.notify_one();
}

size_t MiningRewardsManager::GetPendingShareCount() const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return m_share_queue.size();
}

void MiningRewardsManager::SubmissionThread() {
    LogPrintf("MiningRewards: Submission thread started\n");

    while (m_running.load()) {
        // Wait for batch interval or wake signal
        {
            std::unique_lock<std::mutex> lock(m_cv_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(m_config.batch_interval_seconds));
        }

        if (!m_running.load()) break;

        // Collect pending shares
        std::vector<ShareSubmission> batch;
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            while (!m_share_queue.empty() && batch.size() < static_cast<size_t>(m_config.max_batch_size)) {
                batch.push_back(m_share_queue.front());
                m_share_queue.pop();
            }
        }

        // Submit batch
        if (!batch.empty()) {
            if (SubmitSharesBatch(batch)) {
                m_total_shares_submitted += batch.size();
                LogPrintf("MiningRewards: Submitted %zu shares to contract\n", batch.size());
            } else {
                // Re-queue failed shares
                std::lock_guard<std::mutex> lock(m_queue_mutex);
                for (const auto& share : batch) {
                    m_share_queue.push(share);
                }
                LogPrintf("MiningRewards: Failed to submit shares, re-queued\n");
            }
        }

        // Check for block finalization
        bool should_finalize = false;
        {
            std::lock_guard<std::mutex> lock(m_block_mutex);
            if (m_block_found) {
                should_finalize = true;
                m_block_found = false;
            }
        }

        if (should_finalize) {
            if (FinalizeBlock()) {
                m_total_blocks_finalized++;
                LogPrintf("MiningRewards: Block finalized on contract\n");
            }
        }
    }

    LogPrintf("MiningRewards: Submission thread stopped\n");
}

bool MiningRewardsManager::SubmitSharesBatch(const std::vector<ShareSubmission>& shares) {
    // Submit each share individually (could be optimized with batch contract function)
    for (const auto& share : shares) {
        std::string calldata = BuildSubmitSharesCalldata(share);
        std::string txhash = SendContractTransaction(calldata, 150000);

        if (txhash.empty()) {
            LogPrintf("MiningRewards: Failed to submit share for %s\n",
                      share.miner_address.substr(0, 10));
            return false;
        }

        m_total_tx_sent++;
    }

    return true;
}

bool MiningRewardsManager::FinalizeBlock() {
    std::string calldata = BuildFinalizeBlockCalldata();
    std::string txhash = SendContractTransaction(calldata, 100000);

    if (txhash.empty()) {
        LogPrintf("MiningRewards: Failed to finalize block\n");
        return false;
    }

    m_total_tx_sent++;
    return true;
}

std::string MiningRewardsManager::BuildSubmitSharesCalldata(const ShareSubmission& share) {
    // submitShares(address miner, uint256 shares, bool xmrValid, bool wtxValid, uint256 moneroHeight, uint256 wattxHeight)
    std::ostringstream ss;

    ss << SUBMIT_SHARES_SELECTOR;
    ss << EncodeAddress(share.miner_address);
    ss << EncodeUint256(share.shares);
    ss << EncodeBool(share.xmr_valid);
    ss << EncodeBool(share.wtx_valid);
    ss << EncodeUint256(share.monero_height);
    ss << EncodeUint256(share.wattx_height);

    return ss.str();
}

std::string MiningRewardsManager::BuildFinalizeBlockCalldata() {
    // finalizeBlock()
    return FINALIZE_BLOCK_SELECTOR;
}

std::string MiningRewardsManager::SendContractTransaction(const std::string& calldata, uint64_t gas) {
    // Build eth_sendTransaction params
    std::ostringstream params;
    params << "[{";
    params << "\"from\":\"" << m_config.operator_address << "\",";
    params << "\"to\":\"" << m_config.contract_address << "\",";
    params << "\"gas\":\"0x" << std::hex << gas << "\",";
    params << "\"data\":\"" << calldata << "\"";
    params << "}]";

    std::string response = WattxRPC("eth_sendTransaction", params.str());

    if (response.empty()) {
        return "";
    }

    // Parse transaction hash from response
    size_t pos = response.find("\"result\"");
    if (pos == std::string::npos) {
        return "";
    }

    pos = response.find("\"0x", pos);
    if (pos == std::string::npos) {
        return "";
    }

    size_t end = response.find("\"", pos + 1);
    if (end == std::string::npos) {
        return "";
    }

    return response.substr(pos + 1, end - pos - 1);
}

std::string MiningRewardsManager::WattxRPC(const std::string& method, const std::string& params) {
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"id\":\"mining_rewards\",\"method\":\"" << method << "\",";
    body << "\"params\":" << params << "}";

    std::string auth;
    if (!m_config.wattx_rpc_user.empty()) {
        auth = m_config.wattx_rpc_user + ":" + m_config.wattx_rpc_pass;
    }

    return HttpPost(m_config.wattx_rpc_host, m_config.wattx_rpc_port, "/", body.str(), auth);
}

std::string MiningRewardsManager::HttpPost(const std::string& host, uint16_t port,
                                            const std::string& path, const std::string& body,
                                            const std::string& auth) {
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

std::string MiningRewardsManager::EncodeAddress(const std::string& address) {
    // Remove 0x prefix if present
    std::string addr = address;
    if (addr.length() >= 2 && addr[0] == '0' && addr[1] == 'x') {
        addr = addr.substr(2);
    }

    // Pad to 64 characters (32 bytes) with leading zeros
    std::ostringstream ss;
    ss << std::setfill('0') << std::setw(64) << addr;
    return ss.str();
}

std::string MiningRewardsManager::EncodeUint256(uint64_t value) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(64) << value;
    return ss.str();
}

std::string MiningRewardsManager::EncodeBool(bool value) {
    return EncodeUint256(value ? 1 : 0);
}

}  // namespace mining_rewards
