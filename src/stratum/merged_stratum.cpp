// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stratum/merged_stratum.h>
#include <anchor/evm_anchor.h>
#include <arith_uint256.h>
#include <auxpow/auxpow.h>
#include <hash.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <node/randomx_miner.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
// Windows compatibility for POSIX socket functions
#define poll WSAPoll
#define close closesocket
typedef int socklen_t;
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#else
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// JSON parsing helpers (simple implementation)
#include <sstream>

namespace merged_stratum {

// ============================================================================
// Global Instance
// ============================================================================

static MergedStratumServer g_merged_stratum_server;

MergedStratumServer& GetMergedStratumServer() {
    return g_merged_stratum_server;
}

// ============================================================================
// Simple JSON helpers
// ============================================================================

static std::string JsonEscape(const std::string& s) {
    std::string result;
    for (char c : s) {
        if (c == '"') result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else result += c;
    }
    return result;
}

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

    // Non-string value
    size_t end = json.find_first_of(",}]", pos);
    if (end == std::string::npos) end = json.length();
    std::string value = json.substr(pos, end - pos);
    // Trim whitespace
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.pop_back();
    return value;
}

static std::vector<std::string> ParseJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return result;

    pos += search.length();
    while (pos < json.length() && json[pos] != '[') pos++;
    if (pos >= json.length()) return result;
    pos++;  // Skip '['

    while (pos < json.length() && json[pos] != ']') {
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == ',')) pos++;
        if (json[pos] == ']') break;

        if (json[pos] == '"') {
            pos++;
            size_t end = json.find('"', pos);
            if (end == std::string::npos) break;
            result.push_back(json.substr(pos, end - pos));
            pos = end + 1;
        } else {
            size_t end = json.find_first_of(",]", pos);
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

// ============================================================================
// Varint and Merkle Tree Helpers
// ============================================================================

// Helper: Read a varint from blob at position, returns bytes read
static size_t ReadVarint(const std::vector<uint8_t>& blob, size_t pos, uint64_t& value) {
    value = 0;
    size_t bytes_read = 0;
    int shift = 0;
    while (pos + bytes_read < blob.size()) {
        uint8_t byte = blob[pos + bytes_read];
        bytes_read++;
        value |= (uint64_t)(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) break;
        shift += 7;
        if (shift > 63) break;  // Overflow protection
    }
    return bytes_read;
}

// Helper: Calculate Monero tree hash (merkle root)
static uint256 CalculateMoneroTreeHash(const std::vector<uint256>& hashes) {
    if (hashes.empty()) {
        return uint256();
    }
    if (hashes.size() == 1) {
        return hashes[0];
    }

    // Monero uses a specific tree hash algorithm
    // For 2 elements: H(h0 || h1)
    // For more: recursive tree construction
    std::vector<uint256> tree = hashes;

    while (tree.size() > 1) {
        std::vector<uint256> next_level;
        for (size_t i = 0; i < tree.size(); i += 2) {
            if (i + 1 < tree.size()) {
                // Hash pair
                std::vector<uint8_t> combined;
                combined.insert(combined.end(), tree[i].begin(), tree[i].end());
                combined.insert(combined.end(), tree[i+1].begin(), tree[i+1].end());
                next_level.push_back(Hash(combined));
            } else {
                // Odd element, promote to next level
                next_level.push_back(tree[i]);
            }
        }
        tree = std::move(next_level);
    }

    return tree[0];
}

// Helper: Build merkle branch for proving inclusion at index
static std::vector<uint256> BuildMerkleBranch(const std::vector<uint256>& hashes, int index) {
    std::vector<uint256> branch;
    if (hashes.size() <= 1) {
        return branch;  // No branch needed for single element
    }

    std::vector<uint256> tree = hashes;
    int idx = index;

    while (tree.size() > 1) {
        // Add sibling to branch
        int sibling_idx = (idx & 1) ? idx - 1 : idx + 1;
        if (sibling_idx < (int)tree.size()) {
            branch.push_back(tree[sibling_idx]);
        } else if (idx < (int)tree.size()) {
            // No sibling (odd count), use self
            branch.push_back(tree[idx]);
        }

        // Build next level
        std::vector<uint256> next_level;
        for (size_t i = 0; i < tree.size(); i += 2) {
            if (i + 1 < tree.size()) {
                std::vector<uint8_t> combined;
                combined.insert(combined.end(), tree[i].begin(), tree[i].end());
                combined.insert(combined.end(), tree[i+1].begin(), tree[i+1].end());
                next_level.push_back(Hash(combined));
            } else {
                next_level.push_back(tree[i]);
            }
        }
        tree = std::move(next_level);
        idx >>= 1;
    }

    return branch;
}

// ============================================================================
// MergedStratumServer Implementation
// ============================================================================

MergedStratumServer::MergedStratumServer() = default;

MergedStratumServer::~MergedStratumServer() {
    Stop();
}

bool MergedStratumServer::Start(const MergedStratumConfig& config, interfaces::Mining* wattxMining) {
    if (m_running.load()) {
        LogPrintf("MergedStratum: Already running\n");
        return false;
    }

    m_config = config;
    m_wattx_mining = wattxMining;

    // Create listening socket
    m_listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_listen_socket < 0) {
        LogPrintf("MergedStratum: Failed to create socket\n");
        return false;
    }

    // Set socket options
    int opt = 1;
    setsockopt(m_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    // Bind
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_config.port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LogPrintf("MergedStratum: Failed to bind to port %d\n", m_config.port);
        close(m_listen_socket);
        m_listen_socket = -1;
        return false;
    }

    if (listen(m_listen_socket, 10) < 0) {
        LogPrintf("MergedStratum: Failed to listen\n");
        close(m_listen_socket);
        m_listen_socket = -1;
        return false;
    }

    m_running.store(true);

    // Start threads
    m_accept_thread = std::thread(&MergedStratumServer::AcceptThread, this);
    m_job_thread = std::thread(&MergedStratumServer::JobThread, this);
    m_monero_poller_thread = std::thread(&MergedStratumServer::MoneroPollerThread, this);

    LogPrintf("MergedStratum: Merged mining server started on port %d\n", m_config.port);
    LogPrintf("MergedStratum: Monero daemon: %s:%d\n",
              m_config.monero_daemon_host, m_config.monero_daemon_port);

    return true;
}

void MergedStratumServer::Stop() {
    if (!m_running.load()) return;

    LogPrintf("MergedStratum: Stopping merged mining server...\n");
    m_running.store(false);

    // Wake up job thread
    m_job_cv.notify_all();

    // Close listening socket
    if (m_listen_socket >= 0) {
        close(m_listen_socket);
        m_listen_socket = -1;
    }

    // Disconnect all clients
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (auto& [id, client] : m_clients) {
            if (client && client->socket_fd >= 0) {
                close(client->socket_fd);
            }
        }
        m_clients.clear();
    }

    // Join threads
    if (m_accept_thread.joinable()) m_accept_thread.join();
    if (m_job_thread.joinable()) m_job_thread.join();
    if (m_monero_poller_thread.joinable()) m_monero_poller_thread.join();
    for (auto& t : m_client_threads) {
        if (t.joinable()) t.join();
    }
    m_client_threads.clear();

    LogPrintf("MergedStratum: Server stopped\n");
}

size_t MergedStratumServer::GetClientCount() const {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    return m_clients.size();
}

void MergedStratumServer::NotifyNewMoneroBlock() {
    LogPrintf("MergedStratum: New Monero block notification\n");
    m_job_cv.notify_all();
}

void MergedStratumServer::NotifyNewWattxBlock() {
    LogPrintf("MergedStratum: New WATTx block notification\n");
    m_job_cv.notify_all();
}

// ============================================================================
// Server Threads
// ============================================================================

void MergedStratumServer::AcceptThread() {
    LogPrintf("MergedStratum: Accept thread started\n");

    while (m_running.load()) {
        struct pollfd pfd{};
        pfd.fd = m_listen_socket;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 1000);  // 1 second timeout
        if (ret <= 0) continue;

        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(m_listen_socket, (struct sockaddr*)&client_addr, &addr_len);

        if (client_fd < 0) continue;

        // Create new client
        int client_id;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);

            if (m_clients.size() >= static_cast<size_t>(m_config.max_clients)) {
                LogPrintf("MergedStratum: Max clients reached, rejecting connection\n");
                close(client_fd);
                continue;
            }

            client_id = m_next_client_id++;
            auto client = std::make_unique<MergedClient>();
            client->socket_fd = client_fd;
            client->session_id = GenerateSessionId();
            client->connect_time = GetTime();
            client->last_activity = GetTime();
            m_clients[client_id] = std::move(client);
        }

        // Start client handler thread
        m_client_threads.emplace_back(&MergedStratumServer::ClientThread, this, client_id);

        LogPrintf("MergedStratum: Client %d connected\n", client_id);
    }

    LogPrintf("MergedStratum: Accept thread stopped\n");
}

void MergedStratumServer::ClientThread(int client_id) {
    char buffer[4096];

    while (m_running.load()) {
        int socket_fd;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it == m_clients.end() || !it->second) {
                break;
            }
            socket_fd = it->second->socket_fd;
        }

        struct pollfd pfd{};
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) break;
        if (ret == 0) continue;

        int bytes = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            break;
        }

        buffer[bytes] = '\0';

        // Add to receive buffer and process complete messages
        std::string messages;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it == m_clients.end() || !it->second) break;

            it->second->recv_buffer += buffer;
            it->second->last_activity = GetTime();
            messages = it->second->recv_buffer;
        }

        // Process complete JSON-RPC messages (newline delimited)
        size_t pos = 0;
        while ((pos = messages.find('\n')) != std::string::npos) {
            std::string message = messages.substr(0, pos);
            messages = messages.substr(pos + 1);

            if (!message.empty()) {
                HandleMessage(client_id, message);
            }
        }

        // Store remaining buffer
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it != m_clients.end() && it->second) {
                it->second->recv_buffer = messages;
            }
        }
    }

    DisconnectClient(client_id);
}

void MergedStratumServer::JobThread() {
    LogPrintf("MergedStratum: Job thread started\n");

    while (m_running.load()) {
        // Create new merged job
        CreateMergedJob();

        // Wait for notification or timeout
        std::unique_lock<std::mutex> lock(m_job_cv_mutex);
        m_job_cv.wait_for(lock, std::chrono::seconds(m_config.job_timeout_seconds));
    }

    LogPrintf("MergedStratum: Job thread stopped\n");
}

void MergedStratumServer::MoneroPollerThread() {
    LogPrintf("MergedStratum: Monero poller thread started\n");

    uint64_t last_height = 0;

    while (m_running.load()) {
        std::string blob, seed_hash;
        uint64_t height, difficulty;

        if (GetMoneroBlockTemplate(blob, seed_hash, height, difficulty)) {
            std::lock_guard<std::mutex> lock(m_monero_mutex);

            if (height != last_height) {
                LogPrintf("MergedStratum: New Monero block at height %lu, difficulty %lu\n",
                          height, difficulty);
                last_height = height;

                m_monero_blob = blob;
                m_monero_seed_hash = seed_hash;
                m_monero_height = height;
                m_monero_difficulty = difficulty;

                // Trigger new job creation
                m_job_cv.notify_all();
            }
        }

        // Poll every 5 seconds
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    LogPrintf("MergedStratum: Monero poller thread stopped\n");
}

// ============================================================================
// Protocol Handlers (XMRig JSON-RPC style)
// ============================================================================

void MergedStratumServer::HandleMessage(int client_id, const std::string& message) {
    // Parse JSON-RPC method
    std::string method = ParseJsonString(message, "method");
    std::string id = ParseJsonString(message, "id");

    LogPrintf("MergedStratum: Client %d message: method='%s' id='%s' len=%zu\n",
              client_id, method, id, message.length());

    if (method == "login") {
        // XMRig sends params as object: {"login":"...", "pass":"...", "agent":"..."}
        std::string login = ParseJsonString(message, "login");
        std::string pass = ParseJsonString(message, "pass");
        std::string agent = ParseJsonString(message, "agent");
        // Check if params is nested under "params" object
        size_t params_pos = message.find("\"params\"");
        if (params_pos != std::string::npos && login.empty()) {
            // Extract from nested params object
            std::string params_str = message.substr(params_pos);
            login = ParseJsonString(params_str, "login");
            pass = ParseJsonString(params_str, "pass");
            agent = ParseJsonString(params_str, "agent");
        }
        std::vector<std::string> params = {login, pass, agent};
        HandleLogin(client_id, id, params);
    } else if (method == "submit") {
        // XMRig submit: {"id":"...", "job_id":"...", "nonce":"...", "result":"..."}
        std::string job_id, nonce, result;
        // Check nested params object first
        size_t params_pos = message.find("\"params\"");
        if (params_pos != std::string::npos) {
            std::string params_str = message.substr(params_pos);
            job_id = ParseJsonString(params_str, "job_id");
            nonce = ParseJsonString(params_str, "nonce");
            result = ParseJsonString(params_str, "result");
        }
        // Fallback to top-level (shouldn't happen with XMRig)
        if (job_id.empty()) {
            job_id = ParseJsonString(message, "job_id");
            nonce = ParseJsonString(message, "nonce");
            result = ParseJsonString(message, "result");
        }
        std::vector<std::string> params = {job_id, nonce, result};
        HandleSubmit(client_id, id, params);
    } else if (method == "getjob") {
        HandleGetJob(client_id, id);
    } else if (method == "keepalived") {
        // Just acknowledge
        SendResult(client_id, id, "{\"status\":\"KEEPALIVED\"}");
    } else {
        LogPrintf("MergedStratum: Unknown method '%s' from client %d\n", method, client_id);
        SendError(client_id, id, -1, "Unknown method");
    }
}

void MergedStratumServer::HandleLogin(int client_id, const std::string& id,
                                       const std::vector<std::string>& params) {
    // XMRig login format: params contain login (wallet address), pass, agent
    std::string login, pass, agent;

    if (params.size() >= 1) login = params[0];
    if (params.size() >= 2) pass = params[1];
    if (params.size() >= 3) agent = params[2];

    // Parse wallet addresses from login string
    // Format: "XMR_ADDRESS.WORKER" or "XMR_ADDRESS+WTX_ADDRESS.WORKER"
    std::string xmr_address, wtx_address, worker;

    size_t plus_pos = login.find('+');
    size_t dot_pos = login.find('.');

    if (plus_pos != std::string::npos) {
        // Dual address format
        xmr_address = login.substr(0, plus_pos);
        if (dot_pos != std::string::npos && dot_pos > plus_pos) {
            wtx_address = login.substr(plus_pos + 1, dot_pos - plus_pos - 1);
            worker = login.substr(dot_pos + 1);
        } else {
            wtx_address = login.substr(plus_pos + 1);
        }
    } else if (dot_pos != std::string::npos) {
        xmr_address = login.substr(0, dot_pos);
        worker = login.substr(dot_pos + 1);
    } else {
        xmr_address = login;
    }

    // Use pool's WTX address if not provided
    if (wtx_address.empty()) {
        wtx_address = m_config.wattx_wallet_address;
    }

    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) {
            return;
        }

        it->second->xmr_address = xmr_address;
        it->second->wtx_address = wtx_address;
        it->second->worker_name = worker.empty() ? "default" : worker;
        it->second->authorized = true;
        it->second->subscribed = true;
    }

    LogPrintf("MergedStratum: Client %d logged in (XMR: %s, WTX: %s, worker: %s)\n",
              client_id, xmr_address.substr(0, 16), wtx_address.substr(0, 16), worker);

    // Send login response with first job
    MergedJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        job = m_current_job;
    }

    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end() && it->second) {
            session_id = it->second->session_id;
        }
    }

    // XMRig login response format
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"result\":{";
    oss << "\"id\":\"" << session_id << "\",";
    oss << "\"job\":{";
    oss << "\"blob\":\"" << job.monero_blob << "\",";
    oss << "\"job_id\":\"" << job.job_id << "\",";
    oss << "\"target\":\"" << job.monero_target.GetHex().substr(0, 8) << "\",";
    oss << "\"height\":" << job.monero_height << ",";
    oss << "\"seed_hash\":\"" << job.monero_seed_hash << "\"";
    oss << "},";
    oss << "\"status\":\"OK\"";
    oss << "}}\n";

    SendToClient(client_id, oss.str());
}

void MergedStratumServer::HandleSubmit(int client_id, const std::string& id,
                                        const std::vector<std::string>& params) {
    // XMRig submit format: job_id, nonce, result (hash)
    if (params.size() < 3) {
        SendError(client_id, id, -1, "Invalid params");
        return;
    }

    std::string job_id = params[0];
    std::string nonce = params[1];
    std::string result = params[2];

    bool valid = ValidateShare(client_id, job_id, nonce, result);

    if (valid) {
        SendResult(client_id, id, "{\"status\":\"OK\"}");
    } else {
        SendError(client_id, id, -1, "Invalid share");
    }
}

void MergedStratumServer::HandleGetJob(int client_id, const std::string& id) {
    MergedJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        job = m_current_job;
    }

    SendJob(client_id, job);
}

// ============================================================================
// Job Management
// ============================================================================

void MergedStratumServer::CreateMergedJob() {
    MergedJob job;
    job.job_id = GenerateJobId();
    job.created_at = GetTime();

    // Get WATTx template first (needed for merge mining commitment)
    if (m_wattx_mining) {
        job.wattx_template = m_wattx_mining->createNewBlock();
        if (job.wattx_template) {
            auto header = job.wattx_template->getBlockHeader();
            // Get height from tip + 1 (new block being mined)
            auto tip = m_wattx_mining->getTip();
            job.wattx_height = tip ? tip->height + 1 : 0;
            job.wattx_bits = header.nBits;

            // Calculate WATTx target from nBits
            arith_uint256 target;
            target.SetCompact(job.wattx_bits);
            job.wattx_target = ArithToUint256(target);

            // Create WATTx commitment for Monero coinbase
            uint256 wattx_hash = header.GetHash();
            job.aux_merkle_root = auxpow::CalcAuxChainMerkleRoot(wattx_hash,
                                                                  CAuxPowBlockHeader::WATTX_CHAIN_ID);
            job.merge_mining_tag = auxpow::BuildMergeMiningTag(job.aux_merkle_root, 0);

            // Serialize WATTx blob for reference
            auto blob = node::RandomXMiner::SerializeMiningBlob(header);
            job.wattx_blob = HexStr(blob);
        }
    }

    // Get extended Monero template with coinbase data for AuxPoW
    // This fetches fresh template with reserve space for merge mining tag
    if (!GetMoneroBlockTemplateExtended(job)) {
        // Fallback to cached basic data if extended fetch fails
        std::lock_guard<std::mutex> lock(m_monero_mutex);
        job.monero_blob = m_monero_blob;
        job.monero_seed_hash = m_monero_seed_hash;
        job.monero_height = m_monero_height;
        job.monero_difficulty = m_monero_difficulty;

        LogPrintf("MergedStratum: Using cached Monero template (extended fetch failed)\n");
    }

    // Calculate Monero target from difficulty
    // Monero formula: target = (2^256 - 1) / difficulty
    if (job.monero_difficulty > 0) {
        // Create max uint256 (2^256 - 1) = all 0xff bytes
        uint256 max_uint256;
        std::memset(max_uint256.data(), 0xff, 32);
        arith_uint256 max_target = UintToArith256(max_uint256);
        arith_uint256 target = max_target / job.monero_difficulty;
        job.monero_target = ArithToUint256(target);
    }

    // If no Monero template yet, create a placeholder
    if (job.monero_blob.empty()) {
        // 76-byte placeholder blob
        job.monero_blob = std::string(152, '0');  // 76 bytes hex
        job.monero_seed_hash = std::string(64, '0');
        job.monero_height = 0;
        job.monero_difficulty = 1000;
    }

    // Create EVM transaction anchor if anchoring is active
    auto& anchor_mgr = evm_anchor::GetEVMAnchorManager();
    if (anchor_mgr.IsActive(job.wattx_height) && job.wattx_template) {
        // Get the block being mined
        auto block = job.wattx_template->getBlock();

        // Create anchor with EVM tx references
        job.evm_anchor = anchor_mgr.CreateAnchor(
            job.wattx_height,
            anchor_mgr.GetEVMTransactionHashes(block),
            block.hashStateRoot,
            block.hashUTXORoot,
            block.nTime
        );

        // Build the anchor tag for Monero coinbase extra
        job.evm_anchor_tag = anchor_mgr.BuildAnchorTag(job.evm_anchor);

        LogPrintf("MergedStratum: EVM anchor created - block %d, %d EVM txs, merkle: %s\n",
                  job.evm_anchor.wattx_block_height,
                  job.evm_anchor.evm_tx_count,
                  job.evm_anchor.evm_merkle_root.GetHex().substr(0, 16));
    }

    // Inject WATTx commitment into Monero coinbase and recalculate hashes
    if (!job.merge_mining_tag.empty() && job.monero_coinbase.IsValid()) {
        // Inject merge mining tag into coinbase tx_extra at reserved offset
        if (job.monero_coinbase.reserve_offset > 0 &&
            job.monero_coinbase.reserve_size >= job.merge_mining_tag.size()) {

            // Modify the coinbase transaction with the merge mining tag
            std::vector<uint8_t> modified_coinbase = job.monero_coinbase.coinbase_tx;

            // Calculate offset within coinbase_tx (reserve_offset is absolute in blob)
            // The coinbase starts at a certain position in the original blob
            // We stored reserve_offset as the absolute position of extra field start
            // We need to find the relative position within coinbase_tx

            // Find the extra field in coinbase_tx by parsing it again
            size_t pos = 0;
            uint64_t temp;

            // Skip: version, unlock_time
            pos += ReadVarint(modified_coinbase, pos, temp);  // version
            pos += ReadVarint(modified_coinbase, pos, temp);  // unlock_time

            // Skip inputs
            uint64_t vin_count;
            pos += ReadVarint(modified_coinbase, pos, vin_count);
            for (uint64_t i = 0; i < vin_count && pos < modified_coinbase.size(); i++) {
                uint8_t input_type = modified_coinbase[pos++];
                if (input_type == 0xff) {
                    pos += ReadVarint(modified_coinbase, pos, temp);  // height
                }
            }

            // Skip outputs
            uint64_t vout_count;
            pos += ReadVarint(modified_coinbase, pos, vout_count);
            for (uint64_t i = 0; i < vout_count && pos < modified_coinbase.size(); i++) {
                pos += ReadVarint(modified_coinbase, pos, temp);  // amount
                if (pos < modified_coinbase.size()) {
                    uint8_t out_type = modified_coinbase[pos++];
                    if (out_type == 2) pos += 32;
                    else if (out_type == 3) pos += 33;
                    else pos += 32;  // guess
                }
            }

            // Now at extra length
            uint64_t extra_len;
            pos += ReadVarint(modified_coinbase, pos, extra_len);
            size_t extra_start = pos;

            // Inject merge mining tag at the beginning of extra (after any required fields)
            // Monero extra format: series of tagged fields
            // We insert at the reserved space position

            if (extra_start + extra_len <= modified_coinbase.size()) {
                // Find reserved space in extra (usually at the end, filled with zeros)
                // The reserved_offset from get_block_template points to this
                size_t inject_pos = extra_start;  // Start of extra

                // Look for zeros (reserved space) to overwrite
                for (size_t i = extra_start; i < extra_start + extra_len; i++) {
                    if (modified_coinbase[i] == 0) {
                        inject_pos = i;
                        break;
                    }
                }

                // Write merge mining tag
                if (inject_pos + job.merge_mining_tag.size() <= modified_coinbase.size()) {
                    std::memcpy(&modified_coinbase[inject_pos],
                               job.merge_mining_tag.data(),
                               job.merge_mining_tag.size());

                    // Also inject EVM anchor tag if present
                    if (!job.evm_anchor_tag.empty() &&
                        inject_pos + job.merge_mining_tag.size() + job.evm_anchor_tag.size() <= modified_coinbase.size()) {
                        std::memcpy(&modified_coinbase[inject_pos + job.merge_mining_tag.size()],
                                   job.evm_anchor_tag.data(),
                                   job.evm_anchor_tag.size());
                    }

                    // Update the coinbase data with modified transaction
                    job.monero_coinbase.coinbase_tx = modified_coinbase;

                    // Recalculate coinbase hash
                    uint256 new_coinbase_hash = Hash(modified_coinbase);

                    // Rebuild merkle tree with new coinbase hash
                    // We need to recalculate the tree root
                    // For now, update the tx_merkle_root (this will be used in parent block header)
                    if (job.monero_coinbase.merkle_branch.empty()) {
                        // Single tx (coinbase only) - root is the coinbase hash
                        job.monero_coinbase.tx_merkle_root = new_coinbase_hash;
                    } else {
                        // Multiple txs - recalculate root from branch
                        uint256 root = new_coinbase_hash;
                        int idx = job.monero_coinbase.coinbase_index;
                        for (const auto& branch_hash : job.monero_coinbase.merkle_branch) {
                            if (idx & 1) {
                                std::vector<uint8_t> combined;
                                combined.insert(combined.end(), branch_hash.begin(), branch_hash.end());
                                combined.insert(combined.end(), root.begin(), root.end());
                                root = Hash(combined);
                            } else {
                                std::vector<uint8_t> combined;
                                combined.insert(combined.end(), root.begin(), root.end());
                                combined.insert(combined.end(), branch_hash.begin(), branch_hash.end());
                                root = Hash(combined);
                            }
                            idx >>= 1;
                        }
                        job.monero_coinbase.tx_merkle_root = root;
                    }

                    // Rebuild the hashing blob with new merkle root
                    // The blockhashing_blob needs to be reconstructed
                    std::vector<uint8_t> new_hashing_blob;
                    new_hashing_blob.reserve(76);

                    // Major version
                    new_hashing_blob.push_back(job.monero_coinbase.major_version);
                    // Minor version
                    new_hashing_blob.push_back(job.monero_coinbase.minor_version);
                    // Timestamp as varint
                    uint64_t ts = job.monero_coinbase.timestamp;
                    while (ts >= 0x80) {
                        new_hashing_blob.push_back((ts & 0x7F) | 0x80);
                        ts >>= 7;
                    }
                    new_hashing_blob.push_back(static_cast<uint8_t>(ts));
                    // Prev hash
                    new_hashing_blob.insert(new_hashing_blob.end(),
                                           job.monero_coinbase.prev_hash.begin(),
                                           job.monero_coinbase.prev_hash.end());
                    // Nonce (4 bytes, zeros - miner will fill)
                    new_hashing_blob.push_back(0);
                    new_hashing_blob.push_back(0);
                    new_hashing_blob.push_back(0);
                    new_hashing_blob.push_back(0);
                    // Tree root (merkle root)
                    new_hashing_blob.insert(new_hashing_blob.end(),
                                           job.monero_coinbase.tx_merkle_root.begin(),
                                           job.monero_coinbase.tx_merkle_root.end());
                    // Pad to 76 bytes
                    while (new_hashing_blob.size() < 76) {
                        new_hashing_blob.push_back(0);
                    }

                    job.monero_blob = HexStr(new_hashing_blob);

                    LogPrintf("MergedStratum: Injected MM tag into coinbase, new merkle root: %s\n",
                              job.monero_coinbase.tx_merkle_root.GetHex().substr(0, 16));
                }
            }
        }

        LogPrintf("MergedStratum: Created merged job %s (XMR height: %lu, WTX height: %lu, EVM anchor: %s)\n",
                  job.job_id, job.monero_height, job.wattx_height,
                  job.evm_anchor_tag.empty() ? "no" : "yes");
    }

    // Store job
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        m_current_job = job;
        m_jobs[job.job_id] = job;

        // Cleanup old jobs
        int64_t now = GetTime();
        for (auto it = m_jobs.begin(); it != m_jobs.end();) {
            if (now - it->second.created_at > m_config.job_timeout_seconds * 10) {
                it = m_jobs.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Broadcast to all clients
    BroadcastJob(job);
}

void MergedStratumServer::BroadcastJob(const MergedJob& job) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);

    for (const auto& [client_id, client] : m_clients) {
        if (client && client->authorized) {
            SendJob(client_id, job);
        }
    }
}

bool MergedStratumServer::ValidateShare(int client_id, const std::string& job_id,
                                         const std::string& nonce, const std::string& result) {
    // Find the job
    MergedJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto it = m_jobs.find(job_id);
        if (it == m_jobs.end()) {
            LogPrintf("MergedStratum: Client %d submitted for unknown job %s\n",
                      client_id, job_id);
            return false;
        }
        job = it->second;
    }

    // Decode the submitted hash
    std::vector<uint8_t> result_bytes = ParseHex(result);
    if (result_bytes.size() != 32) {
        LogPrintf("MergedStratum: Invalid result hash length from client %d\n", client_id);
        return false;
    }

    uint256 submitted_hash;
    std::memcpy(submitted_hash.data(), result_bytes.data(), 32);

    // Convert to arith for comparison
    arith_uint256 hash_arith = UintToArith256(submitted_hash);

    // Calculate share target (easier than network target for tracking)
    arith_uint256 share_target = arith_uint256().SetCompact(0x1d00ffff);
    share_target /= m_config.share_difficulty;

    // Check if meets share difficulty
    if (hash_arith > share_target) {
        LogPrintf("MergedStratum: Share from client %d doesn't meet share target\n", client_id);
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it != m_clients.end() && it->second) {
                it->second->shares_rejected++;
            }
        }
        return false;
    }

    // Check if meets Monero network target
    arith_uint256 xmr_target = UintToArith256(job.monero_target);
    bool meets_xmr_target = (hash_arith <= xmr_target);

    // Check if meets WATTx network target
    arith_uint256 wtx_target = UintToArith256(job.wattx_target);
    bool meets_wtx_target = (hash_arith <= wtx_target);

    // Update statistics
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end() && it->second) {
            if (meets_xmr_target) {
                it->second->xmr_shares_accepted++;
                m_total_xmr_shares++;
                LogPrintf("MergedStratum: XMR share from client %d meets network target!\n", client_id);
            }
            if (meets_wtx_target) {
                it->second->wtx_shares_accepted++;
                m_total_wtx_shares++;
                LogPrintf("MergedStratum: WTX share from client %d meets network target!\n", client_id);
            }
        }
    }

    // If meets Monero target, submit to Monero
    if (meets_xmr_target && !job.monero_blob.empty()) {
        // Inject nonce into blob and submit
        std::string blob_with_nonce = job.monero_blob;

        // Nonce goes at position 78-86 (bytes 39-42 in hex)
        if (blob_with_nonce.length() >= 86 && nonce.length() >= 8) {
            blob_with_nonce.replace(78, 8, nonce);

            if (SubmitMoneroBlock(blob_with_nonce)) {
                LogPrintf("MergedStratum: CLIENT %d FOUND MONERO BLOCK!\n", client_id);
                std::lock_guard<std::mutex> lock(m_clients_mutex);
                auto it = m_clients.find(client_id);
                if (it != m_clients.end() && it->second) {
                    it->second->xmr_blocks_found++;
                    m_xmr_blocks_found++;
                }
            }
        }
    }

    // If meets WATTx target, submit to WATTx
    if (meets_wtx_target && job.wattx_template) {
        LogPrintf("MergedStratum: CLIENT %d FOUND WATTX BLOCK! Constructing AuxPoW proof...\n", client_id);

        // Construct and submit the AuxPoW block
        bool block_submitted = ConstructAndSubmitAuxPowBlock(client_id, job, nonce, result);

        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it != m_clients.end() && it->second) {
                if (block_submitted) {
                    it->second->wtx_blocks_found++;
                    m_wtx_blocks_found++;
                    LogPrintf("MergedStratum: CLIENT %d WATTx block ACCEPTED! Total blocks: %lu\n",
                              client_id, m_wtx_blocks_found.load());
                } else {
                    LogPrintf("MergedStratum: CLIENT %d WATTx block submission FAILED\n", client_id);
                }
            }
        }
    }

    LogPrintf("MergedStratum: Valid share from client %d (XMR: %s, WTX: %s)\n",
              client_id, meets_xmr_target ? "YES" : "no", meets_wtx_target ? "YES" : "no");

    // Report share to mining rewards contract
    auto& rewards_mgr = mining_rewards::GetMiningRewardsManager();
    if (rewards_mgr.IsRunning()) {
        mining_rewards::ShareSubmission share;

        // Get miner's WATTx address
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it != m_clients.end() && it->second) {
                share.miner_address = it->second->wtx_address;
            }
        }

        if (!share.miner_address.empty()) {
            share.shares = 1;  // Could weight by share difficulty
            share.xmr_valid = meets_xmr_target;
            share.wtx_valid = meets_wtx_target;
            share.monero_height = job.monero_height;
            share.wattx_height = job.wattx_height;
            share.timestamp = GetTime();

            rewards_mgr.QueueShare(share);
        }
    }

    // Notify rewards manager if block found
    if (meets_xmr_target || meets_wtx_target) {
        auto& rewards_mgr = mining_rewards::GetMiningRewardsManager();
        if (rewards_mgr.IsRunning()) {
            rewards_mgr.NotifyBlockFound(job.monero_height, job.wattx_height);
        }
    }

    return true;
}

// ============================================================================
// Monero Daemon Communication
// ============================================================================

bool MergedStratumServer::GetMoneroBlockTemplate(std::string& blob, std::string& seed_hash,
                                                  uint64_t& height, uint64_t& difficulty) {
    // JSON-RPC request to Monero daemon
    // Reserve size: 34 bytes for merge mining tag + 160 bytes for EVM anchor = 194 bytes
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_template\","
                          "\"params\":{\"wallet_address\":\"" + m_config.monero_wallet_address + "\","
                          "\"reserve_size\":194}}";  // Space for merge mining tag + EVM anchor

    std::string response = HttpPost(m_config.monero_daemon_host, m_config.monero_daemon_port,
                                     "/json_rpc", request);

    if (response.empty()) {
        return false;
    }

    // Parse response
    blob = ParseJsonString(response, "blocktemplate_blob");
    seed_hash = ParseJsonString(response, "seed_hash");

    std::string height_str = ParseJsonString(response, "height");
    std::string diff_str = ParseJsonString(response, "difficulty");

    if (blob.empty()) {
        return false;
    }

    height = height_str.empty() ? 0 : std::stoull(height_str);
    difficulty = diff_str.empty() ? 0 : std::stoull(diff_str);

    return true;
}

bool MergedStratumServer::SubmitMoneroBlock(const std::string& blob) {
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_block\","
                          "\"params\":[\"" + blob + "\"]}";

    std::string response = HttpPost(m_config.monero_daemon_host, m_config.monero_daemon_port,
                                     "/json_rpc", request);

    if (response.empty()) {
        return false;
    }

    // Check for success
    if (response.find("\"status\":\"OK\"") != std::string::npos) {
        return true;
    }

    LogPrintf("MergedStratum: Monero block submission failed: %s\n", response);
    return false;
}

// ============================================================================
// Network Helpers
// ============================================================================

void MergedStratumServer::SendToClient(int client_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    auto it = m_clients.find(client_id);
    if (it == m_clients.end() || !it->second) return;

    send(it->second->socket_fd, message.c_str(), message.length(), MSG_NOSIGNAL);
}

void MergedStratumServer::SendResult(int client_id, const std::string& id, const std::string& result) {
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":" << result << "}\n";
    SendToClient(client_id, oss.str());
}

void MergedStratumServer::SendError(int client_id, const std::string& id, int code, const std::string& msg) {
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"code\":" << code
        << ",\"message\":\"" << JsonEscape(msg) << "\"},\"result\":null}\n";
    SendToClient(client_id, oss.str());
}

void MergedStratumServer::SendJob(int client_id, const MergedJob& job) {
    std::ostringstream oss;
    oss << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{";
    oss << "\"blob\":\"" << job.monero_blob << "\",";
    oss << "\"job_id\":\"" << job.job_id << "\",";
    oss << "\"target\":\"" << job.monero_target.GetHex().substr(0, 8) << "\",";
    oss << "\"height\":" << job.monero_height << ",";
    oss << "\"seed_hash\":\"" << job.monero_seed_hash << "\"";
    oss << "}}\n";
    SendToClient(client_id, oss.str());
}

void MergedStratumServer::DisconnectClient(int client_id) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    auto it = m_clients.find(client_id);
    if (it != m_clients.end()) {
        if (it->second && it->second->socket_fd >= 0) {
            close(it->second->socket_fd);
        }
        m_clients.erase(it);
        LogPrintf("MergedStratum: Client %d disconnected\n", client_id);
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string MergedStratumServer::GenerateJobId() {
    uint64_t counter = m_job_counter++;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << counter;
    return oss.str();
}

std::string MergedStratumServer::GenerateSessionId() {
    unsigned char rand_bytes[16];
    GetRandBytes(rand_bytes);
    return HexStr(rand_bytes);
}

std::string MergedStratumServer::HttpPost(const std::string& host, uint16_t port,
                                           const std::string& path, const std::string& body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    // Set timeout
#ifdef WIN32
    DWORD timeout_ms = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Resolve hostname
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

    // Build HTTP request
    std::ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << ":" << port << "\r\n";
    request << "Content-Type: application/json\r\n";
    request << "Content-Length: " << body.length() << "\r\n";
    request << "Connection: close\r\n\r\n";
    request << body;

    std::string req_str = request.str();
    if (send(sock, req_str.c_str(), req_str.length(), 0) < 0) {
        close(sock);
        return "";
    }

    // Read response
    std::string response;
    char buffer[4096];
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
    }

    close(sock);

    // Extract body (skip headers)
    size_t body_start = response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

// ============================================================================
// Monero Block Parsing and AuxPoW Construction
// ============================================================================

bool MergedStratumServer::ParseMoneroBlockBlob(const std::string& blob_hex,
                                                 MoneroCoinbaseData& coinbase_data) {
    // Monero blocktemplate_blob format:
    // 1. Block header:
    //    - major_version (varint, typically 1 byte)
    //    - minor_version (varint, typically 1 byte)
    //    - timestamp (varint, ~5 bytes)
    //    - prev_id (32 bytes)
    //    - nonce (4 bytes)
    // 2. Miner transaction (coinbase):
    //    - version (varint)
    //    - unlock_time (varint)
    //    - vin_count (varint, always 1 for coinbase)
    //    - vin[0]: gen input (type 0xff + height varint)
    //    - vout_count (varint)
    //    - vout[]: outputs
    //    - extra (with reserved space for merge mining)
    // 3. Number of non-coinbase tx hashes (varint)
    // 4. tx_hashes[] (32 bytes each)

    std::vector<uint8_t> blob = ParseHex(blob_hex);
    if (blob.size() < 100) {
        LogPrintf("MergedStratum: Block blob too short (%zu bytes)\n", blob.size());
        return false;
    }

    size_t pos = 0;
    uint64_t temp;

    // === Parse Block Header ===

    // Major version (varint)
    pos += ReadVarint(blob, pos, temp);
    coinbase_data.major_version = static_cast<uint8_t>(temp);

    // Minor version (varint)
    pos += ReadVarint(blob, pos, temp);
    coinbase_data.minor_version = static_cast<uint8_t>(temp);

    // Timestamp (varint)
    pos += ReadVarint(blob, pos, coinbase_data.timestamp);

    // Previous block hash (32 bytes)
    if (pos + 32 > blob.size()) {
        LogPrintf("MergedStratum: Blob too short for prev_hash at pos %zu\n", pos);
        return false;
    }
    std::memcpy(coinbase_data.prev_hash.data(), &blob[pos], 32);
    pos += 32;

    // Nonce (4 bytes, little-endian)
    if (pos + 4 > blob.size()) {
        LogPrintf("MergedStratum: Blob too short for nonce at pos %zu\n", pos);
        return false;
    }
    coinbase_data.nonce = blob[pos] | (blob[pos+1] << 8) | (blob[pos+2] << 16) | (blob[pos+3] << 24);
    pos += 4;

    // Record where coinbase transaction starts
    size_t coinbase_start = pos;

    // === Parse Coinbase Transaction ===
    // We need to find where it ends to know the boundary

    // TX version (varint)
    pos += ReadVarint(blob, pos, temp);

    // Unlock time (varint)
    pos += ReadVarint(blob, pos, temp);

    // Input count (varint) - should be 1 for coinbase
    uint64_t vin_count;
    pos += ReadVarint(blob, pos, vin_count);

    // Parse inputs
    for (uint64_t i = 0; i < vin_count; i++) {
        if (pos >= blob.size()) return false;
        uint8_t input_type = blob[pos++];

        if (input_type == 0xff) {
            // Gen input (coinbase): just height as varint
            pos += ReadVarint(blob, pos, temp);
        } else {
            // Other input types (shouldn't happen in coinbase)
            LogPrintf("MergedStratum: Unexpected input type 0x%02x in coinbase\n", input_type);
            return false;
        }
    }

    // Output count (varint)
    uint64_t vout_count;
    pos += ReadVarint(blob, pos, vout_count);

    // Parse outputs
    for (uint64_t i = 0; i < vout_count; i++) {
        // Amount (varint)
        pos += ReadVarint(blob, pos, temp);

        // Output type
        if (pos >= blob.size()) return false;
        uint8_t output_type = blob[pos++];

        if (output_type == 2) {
            // txout_to_key: 32-byte public key
            pos += 32;
        } else if (output_type == 3) {
            // txout_to_tagged_key: 32-byte key + 1-byte view tag
            pos += 33;
        } else {
            LogPrintf("MergedStratum: Unknown output type 0x%02x\n", output_type);
            // Try to skip assuming 32 bytes
            pos += 32;
        }

        if (pos > blob.size()) return false;
    }

    // Extra field (varint length + data)
    uint64_t extra_len;
    pos += ReadVarint(blob, pos, extra_len);

    // Record extra field position for tag injection
    coinbase_data.reserve_offset = pos;
    coinbase_data.reserve_size = extra_len;

    // Skip extra field
    pos += extra_len;

    // End of coinbase transaction
    size_t coinbase_end = pos;

    // Store the complete coinbase transaction bytes
    if (coinbase_end > blob.size()) {
        LogPrintf("MergedStratum: Coinbase extends beyond blob\n");
        return false;
    }
    coinbase_data.coinbase_tx.assign(blob.begin() + coinbase_start, blob.begin() + coinbase_end);

    // === Parse Transaction Hashes ===

    // Number of non-coinbase transactions (varint)
    uint64_t tx_hash_count;
    pos += ReadVarint(blob, pos, tx_hash_count);

    // Collect all transaction hashes for merkle tree
    std::vector<uint256> tx_hashes;

    // First hash is the coinbase transaction hash
    // Monero uses keccak for tx hashing, but we'll use our Hash for compatibility
    uint256 coinbase_hash = Hash(coinbase_data.coinbase_tx);
    tx_hashes.push_back(coinbase_hash);

    // Read remaining transaction hashes
    for (uint64_t i = 0; i < tx_hash_count; i++) {
        if (pos + 32 > blob.size()) {
            LogPrintf("MergedStratum: Blob too short for tx hash %lu\n", i);
            return false;
        }
        uint256 tx_hash;
        std::memcpy(tx_hash.data(), &blob[pos], 32);
        tx_hashes.push_back(tx_hash);
        pos += 32;
    }

    // === Calculate Merkle Tree ===

    // Build merkle branch for coinbase (index 0)
    coinbase_data.coinbase_index = 0;
    coinbase_data.merkle_branch = BuildMerkleBranch(tx_hashes, 0);

    // Calculate tree root (this is what goes in the hashing blob)
    coinbase_data.tx_merkle_root = CalculateMoneroTreeHash(tx_hashes);

    LogPrintf("MergedStratum: Parsed Monero blob - version %d.%d, timestamp %lu, "
              "coinbase %zu bytes, %zu txs, merkle branch depth %zu\n",
              coinbase_data.major_version, coinbase_data.minor_version,
              coinbase_data.timestamp, coinbase_data.coinbase_tx.size(),
              tx_hashes.size(), coinbase_data.merkle_branch.size());

    return true;
}

CMoneroBlockHeader MergedStratumServer::BuildMoneroHeader(const MoneroCoinbaseData& coinbase_data,
                                                           uint32_t nonce) {
    CMoneroBlockHeader header;
    header.major_version = coinbase_data.major_version;
    header.minor_version = coinbase_data.minor_version;
    header.timestamp = coinbase_data.timestamp;
    header.prev_id = coinbase_data.prev_hash;
    header.nonce = nonce;
    header.merkle_root = coinbase_data.tx_merkle_root;
    return header;
}

bool MergedStratumServer::GetMoneroBlockTemplateExtended(MergedJob& job) {
    // Request block template with extra reserve size for merge mining tag
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_template\","
                          "\"params\":{\"wallet_address\":\"" + m_config.monero_wallet_address + "\","
                          "\"reserve_size\":194}}";

    std::string response = HttpPost(m_config.monero_daemon_host, m_config.monero_daemon_port,
                                     "/json_rpc", request);

    if (response.empty()) {
        return false;
    }

    // Parse response
    job.monero_blob = ParseJsonString(response, "blockhashing_blob");
    job.monero_blocktemplate_blob = ParseJsonString(response, "blocktemplate_blob");
    job.monero_seed_hash = ParseJsonString(response, "seed_hash");

    std::string height_str = ParseJsonString(response, "height");
    std::string diff_str = ParseJsonString(response, "difficulty");
    std::string reserve_offset_str = ParseJsonString(response, "reserved_offset");

    if (job.monero_blocktemplate_blob.empty()) {
        LogPrintf("MergedStratum: Failed to get blocktemplate_blob from Monero\n");
        return false;
    }

    job.monero_height = height_str.empty() ? 0 : std::stoull(height_str);
    job.monero_difficulty = diff_str.empty() ? 0 : std::stoull(diff_str);

    // Parse the full block template to extract coinbase data
    if (!ParseMoneroBlockBlob(job.monero_blocktemplate_blob, job.monero_coinbase)) {
        LogPrintf("MergedStratum: Failed to parse Monero block blob\n");
        return false;
    }

    // Store reserve offset for merge mining tag injection
    job.monero_coinbase.reserve_offset = reserve_offset_str.empty() ? 0 : std::stoull(reserve_offset_str);
    job.monero_coinbase.reserve_size = 194;

    LogPrintf("MergedStratum: Got extended Monero template - height %lu, reserve offset %zu\n",
              job.monero_height, job.monero_coinbase.reserve_offset);

    return true;
}

bool MergedStratumServer::ConstructAndSubmitAuxPowBlock(int client_id, const MergedJob& job,
                                                          const std::string& nonce_hex,
                                                          const std::string& result_hex) {
    if (!job.wattx_template) {
        LogPrintf("MergedStratum: No WATTx template available for AuxPoW submission\n");
        return false;
    }

    if (!job.monero_coinbase.IsValid()) {
        LogPrintf("MergedStratum: No valid Monero coinbase data for AuxPoW construction\n");
        return false;
    }

    // Parse the submitted nonce (little-endian)
    std::vector<uint8_t> nonce_bytes = ParseHex(nonce_hex);
    if (nonce_bytes.size() < 4) {
        LogPrintf("MergedStratum: Invalid nonce length\n");
        return false;
    }
    uint32_t nonce = nonce_bytes[0] | (nonce_bytes[1] << 8) |
                     (nonce_bytes[2] << 16) | (nonce_bytes[3] << 24);

    // Build the Monero block header with the winning nonce
    CMoneroBlockHeader monero_header = BuildMoneroHeader(job.monero_coinbase, nonce);

    // Create a Bitcoin-style coinbase transaction that wraps the Monero coinbase data
    // This is used for AuxPoW validation - the merge mining tag must be findable
    CMutableTransaction coinbase_tx;
    coinbase_tx.version = 2;

    // Create coinbase input with the actual Monero coinbase data embedded
    CTxIn coinbase_in;
    coinbase_in.prevout.SetNull();

    // The scriptSig contains:
    // 1. Height (BIP34 style)
    // 2. The merge mining tag (so GetAuxChainMerkleRoot can find it)
    // 3. The actual Monero coinbase bytes (for merkle proof verification)
    std::vector<uint8_t> scriptSig_data;

    // Height serialization (BIP34 style) - 3 bytes for heights up to 16M
    scriptSig_data.push_back(0x03);  // Push 3 bytes
    scriptSig_data.push_back(job.monero_height & 0xFF);
    scriptSig_data.push_back((job.monero_height >> 8) & 0xFF);
    scriptSig_data.push_back((job.monero_height >> 16) & 0xFF);

    // Add merge mining tag (TX_EXTRA_MERGE_MINING_TAG format)
    // This allows GetAuxChainMerkleRoot() to find and verify the commitment
    scriptSig_data.insert(scriptSig_data.end(),
                          job.merge_mining_tag.begin(),
                          job.merge_mining_tag.end());

    // Optionally embed EVM anchor tag
    if (!job.evm_anchor_tag.empty()) {
        scriptSig_data.insert(scriptSig_data.end(),
                              job.evm_anchor_tag.begin(),
                              job.evm_anchor_tag.end());
    }

    coinbase_in.scriptSig = CScript(scriptSig_data.begin(), scriptSig_data.end());
    coinbase_tx.vin.push_back(coinbase_in);

    // Add a minimal output
    CTxOut coinbase_out;
    coinbase_out.nValue = 0;
    coinbase_out.scriptPubKey = CScript();
    coinbase_tx.vout.push_back(coinbase_out);

    // Convert merkle branch from uint256 vector to the format CreateAuxPow expects
    std::vector<uint256> merkle_branch = job.monero_coinbase.merkle_branch;

    // Create the AuxPoW proof
    // The proof links: WATTx block hash -> merge mining tag -> Monero coinbase -> Monero block
    CAuxPow auxpow = auxpow::CreateAuxPow(
        job.wattx_template->getBlockHeader(),
        monero_header,
        CTransaction(coinbase_tx),
        merkle_branch,
        job.monero_coinbase.coinbase_index
    );

    // Verify the proof is valid before submitting
    uint256 wattx_block_hash = job.wattx_template->getBlockHeader().GetHash();
    if (!auxpow.Check(wattx_block_hash, CAuxPowBlockHeader::WATTX_CHAIN_ID)) {
        LogPrintf("MergedStratum: AuxPoW self-check failed! Not submitting.\n");
        LogPrintf("MergedStratum:   WATTx block hash: %s\n", wattx_block_hash.GetHex());
        LogPrintf("MergedStratum:   Monero merkle root: %s\n", job.monero_coinbase.tx_merkle_root.GetHex());
        LogPrintf("MergedStratum:   Aux merkle root: %s\n", job.aux_merkle_root.GetHex());
        return false;
    }

    // Get WATTx block parameters
    CBlockHeader wattx_header = job.wattx_template->getBlockHeader();
    CTransactionRef wattx_coinbase = job.wattx_template->getCoinbaseTx();

    // Submit via the mining interface
    auto auxpow_ptr = std::make_shared<CAuxPow>(auxpow);

    bool success = job.wattx_template->submitAuxPowSolution(
        wattx_header.nVersion | CAuxPowBlockHeader::AUXPOW_VERSION_FLAG,
        wattx_header.nTime,
        0,  // nNonce not used for AuxPoW
        wattx_coinbase,
        auxpow_ptr
    );

    if (success) {
        LogPrintf("MergedStratum: SUCCESS! AuxPoW block submitted for client %d\n", client_id);
        LogPrintf("MergedStratum:   WATTx height: %lu\n", job.wattx_height);
        LogPrintf("MergedStratum:   Monero height: %lu\n", job.monero_height);
        LogPrintf("MergedStratum:   Monero nonce: 0x%08x\n", nonce);
        LogPrintf("MergedStratum:   Parent PoW hash: %s\n",
                  auxpow.GetParentBlockPoWHash().GetHex().substr(0, 16));
    } else {
        LogPrintf("MergedStratum: AuxPoW block submission failed for client %d\n", client_id);
    }

    return success;
}

}  // namespace merged_stratum
