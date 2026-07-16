// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stratum/multi_merged_stratum.h>
#include <stratum/parent_chain_base.h>  // BuildAuxMergedCoinbase / BuildBitcoinHeader
#include <arith_uint256.h>
#include <auxpow/auxpow.h>
#include <addresstype.h>          // GetScriptForDestination, IsValidDestination
#include <key_io.h>               // DecodeDestination
#include <hash.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>        // OP_RETURN
#include <streams.h>              // DataStream (BTC-stratum coinb1/coinb2 split)
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <set>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
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
#include <sstream>

namespace merged_stratum {

// ============================================================================
// Global Instance
// ============================================================================

static MultiMergedStratumServer g_multi_merged_server;

MultiMergedStratumServer& GetMultiMergedStratumServer() {
    return g_multi_merged_server;
}

// ============================================================================
// JSON Helpers
// ============================================================================

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

static std::vector<std::string> ParseJsonArray(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return result;

    pos += search.length();
    while (pos < json.length() && json[pos] != '[') pos++;
    if (pos >= json.length()) return result;
    pos++;

    while (pos < json.length() && json[pos] != ']') {
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == ',' || json[pos] == '\t')) pos++;
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
// MultiMergedStratumServer Implementation
// ============================================================================

MultiMergedStratumServer::MultiMergedStratumServer() = default;

MultiMergedStratumServer::~MultiMergedStratumServer() {
    Stop();
}

bool MultiMergedStratumServer::Start(const MultiMergedConfig& config, interfaces::Mining* wattxMining) {
    if (m_running.load()) {
        LogPrintf("MultiMergedStratum: Already running\n");
        return false;
    }

    m_config = config;
    m_wattx_mining = wattxMining;

    // Initialize parent chain handlers
    for (const auto& chain_config : config.parent_chains) {
        if (!chain_config.enabled) continue;

        auto handler = ParentChainFactory::Create(chain_config);
        if (!handler) {
            LogPrintf("MultiMergedStratum: Failed to create handler for %s\n", chain_config.name);
            continue;
        }

        m_parent_handlers[chain_config.name] = std::move(handler);

        // Set primary chain for algorithm (first configured chain for each algo)
        if (m_algo_primary_chain.find(chain_config.algo) == m_algo_primary_chain.end()) {
            m_algo_primary_chain[chain_config.algo] = chain_config.name;
        }

        // Initialize statistics
        m_total_shares[chain_config.name] = 0;
        m_blocks_found[chain_config.name] = 0;

        LogPrintf("MultiMergedStratum: Initialized %s handler (%s)\n",
                  chain_config.name, ParentChainFactory::AlgoToString(chain_config.algo));
    }

    if (m_parent_handlers.empty()) {
        LogPrintf("MultiMergedStratum: No parent chains configured\n");
        return false;
    }

    // Create listening sockets for each algorithm
    std::set<ParentChainAlgo> configured_algos;
    for (const auto& [name, handler] : m_parent_handlers) {
        configured_algos.insert(handler->GetAlgo());
    }

    int algo_index = 0;
    for (ParentChainAlgo algo : configured_algos) {
        uint16_t port = config.base_port + algo_index;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            LogPrintf("MultiMergedStratum: Failed to create socket for %s\n",
                      ParentChainFactory::AlgoToString(algo));
            continue;
        }

        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LogPrintf("MultiMergedStratum: Failed to bind port %d for %s\n",
                      port, ParentChainFactory::AlgoToString(algo));
            close(sock);
            continue;
        }

        if (listen(sock, 10) < 0) {
            LogPrintf("MultiMergedStratum: Failed to listen on port %d\n", port);
            close(sock);
            continue;
        }

        m_listen_sockets[algo] = sock;
        LogPrintf("MultiMergedStratum: Listening on port %d for %s\n",
                  port, ParentChainFactory::AlgoToString(algo));

        algo_index++;
    }

    if (m_listen_sockets.empty()) {
        LogPrintf("MultiMergedStratum: Failed to bind any ports\n");
        return false;
    }

    m_running.store(true);
    m_started_at.store(GetTime());

    // Pre-initialize condition variables and mutexes before threads start.
    // JobThread uses operator[] on these maps, which inserts on miss — doing
    // that concurrently across 7 threads is UB on unordered_map.
    for (const auto& [algo, sock] : m_listen_sockets) {
        (void)m_job_cvs[algo];
        (void)m_job_cv_mutexes[algo];
    }

    // Start threads
    for (const auto& [algo, sock] : m_listen_sockets) {
        m_accept_threads.emplace_back(&MultiMergedStratumServer::AcceptThread, this, algo);
        m_job_threads.emplace_back(&MultiMergedStratumServer::JobThread, this, algo);
    }

    // Start poller threads for each parent chain
    for (const auto& [name, handler] : m_parent_handlers) {
        m_poller_threads.emplace_back(&MultiMergedStratumServer::ParentPollerThread, this, name);

        // Initialize coin stats
        m_coin_stats[name] = CoinHashrateStats{};
        m_coin_stats[name].coin_name = name;
        m_coin_stats[name].algo = handler->GetAlgo();
    }

    // Start hashrate tracking thread for cross-algorithm share calculation
    m_hashrate_thread = std::thread(&MultiMergedStratumServer::HashrateUpdateThread, this);

    LogPrintf("MultiMergedStratum: Server started with %zu algorithms, %zu parent chains\n",
              m_listen_sockets.size(), m_parent_handlers.size());
    LogPrintf("MultiMergedStratum: Cross-algorithm share calculation enabled (pool/network hashrate weighting)\n");

    return true;
}

void MultiMergedStratumServer::Stop() {
    if (!m_running.load()) return;

    LogPrintf("MultiMergedStratum: Stopping server...\n");
    m_running.store(false);

    // Wake up job threads
    for (auto& [algo, cv] : m_job_cvs) {
        cv.notify_all();
    }

    // Close listening sockets
    for (auto& [algo, sock] : m_listen_sockets) {
        if (sock >= 0) {
            close(sock);
        }
    }
    m_listen_sockets.clear();

    // Disconnect clients
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
    for (auto& t : m_accept_threads) {
        if (t.joinable()) t.join();
    }
    for (auto& t : m_job_threads) {
        if (t.joinable()) t.join();
    }
    for (auto& t : m_poller_threads) {
        if (t.joinable()) t.join();
    }
    for (auto& t : m_client_threads) {
        if (t.joinable()) t.join();
    }
    if (m_hashrate_thread.joinable()) {
        m_hashrate_thread.join();
    }

    m_accept_threads.clear();
    m_job_threads.clear();
    m_poller_threads.clear();
    m_client_threads.clear();

    // Clear hashrate stats
    {
        std::lock_guard<std::mutex> lock(m_hashrate_mutex);
        m_coin_stats.clear();
    }

    LogPrintf("MultiMergedStratum: Server stopped\n");
}

size_t MultiMergedStratumServer::GetTotalClientCount() const {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    return m_clients.size();
}

size_t MultiMergedStratumServer::GetClientCount(ParentChainAlgo algo) const {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    size_t count = 0;
    for (const auto& [id, client] : m_clients) {
        if (client && client->algo == algo) count++;
    }
    return count;
}

uint16_t MultiMergedStratumServer::GetPort(ParentChainAlgo algo) const {
    int index = 0;
    for (const auto& [a, sock] : m_listen_sockets) {
        if (a == algo) return m_config.base_port + index;
        index++;
    }
    return 0;
}

MultiMergedStratumServer::Dashboard MultiMergedStratumServer::GetDashboard() const {
    Dashboard d;
    d.running = m_running.load();
    d.wtx_blocks_found = m_wtx_blocks_found.load();
    d.started_at = m_started_at.load();

    // Per-algo stats
    static const std::unordered_map<ParentChainAlgo, std::string> algoNames{
        {ParentChainAlgo::SHA256D,    "sha256d"},
        {ParentChainAlgo::SCRYPT,     "scrypt"},
        {ParentChainAlgo::ETHASH,     "ethash"},
        {ParentChainAlgo::RANDOMX,    "randomx"},
        {ParentChainAlgo::EQUIHASH,   "equihash"},
        {ParentChainAlgo::X11,        "x11"},
        {ParentChainAlgo::KHEAVYHASH, "kheavyhash"},
    };

    int port_index = 0;
    for (const auto& [algo, sock] : m_listen_sockets) {
        AlgoStats as;
        as.algo = algoNames.count(algo) ? algoNames.at(algo) : "unknown";
        as.port = m_config.base_port + port_index++;

        // Find primary chain for this algo
        auto pri = m_algo_primary_chain.find(algo);
        if (pri != m_algo_primary_chain.end()) {
            as.chain_name = pri->second;
            auto hit = m_parent_handlers.find(pri->second);
            if (hit != m_parent_handlers.end()) {
                // Config from the handler's config
                for (const auto& pc : m_config.parent_chains) {
                    if (pc.name == pri->second) {
                        as.daemon_host    = pc.daemon_host;
                        as.daemon_port    = pc.daemon_port;
                        as.wallet_address = pc.wallet_address;
                        break;
                    }
                }
            }
            auto sit = m_total_shares.find(pri->second);
            if (sit != m_total_shares.end()) as.shares_accepted = sit->second.load();
        }

        // Count miners on this algo and accumulate per-client stats
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            for (const auto& [id, c] : m_clients) {
                if (!c || c->algo != algo) continue;
                as.miners_connected++;
                for (const auto& [ch, cnt] : c->shares_accepted) (void)ch, as.shares_accepted += cnt;
                as.shares_rejected += c->shares_rejected;
                for (const auto& [ch, cnt] : c->blocks_found) (void)ch, as.parent_blocks_found += cnt;
            }
        }

        d.algos.push_back(std::move(as));
    }

    // Per-miner list
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (const auto& [id, c] : m_clients) {
            if (!c) continue;
            MinerStats ms;
            ms.client_id = id;
            ms.wtx_address = c->wtx_address;
            ms.login = c->wtx_address.empty() ? "unknown" : c->wtx_address;
            // Find algo name
            auto an = algoNames.find(c->algo);
            ms.algo = (an != algoNames.end()) ? an->second : "unknown";
            for (const auto& [ch, cnt] : c->shares_accepted) ms.shares_accepted += cnt;
            ms.shares_rejected = c->shares_rejected;
            ms.wtx_blocks_found = c->wtx_blocks_found;
            ms.connected_since = c->connect_time;
            ms.last_activity = c->last_activity;
            d.miners.push_back(std::move(ms));
        }
    }

    return d;
}

bool MultiMergedStratumServer::UpdateParentChainConfig(
    const std::string& chain_name, const ParentChainConfig& new_config)
{
    // Update stored config so next job cycle picks up new connection params
    for (auto& pc : m_config.parent_chains) {
        if (pc.name == chain_name) {
            pc = new_config;
            // Kick the job thread to reconnect
            auto hit = m_parent_handlers.find(chain_name);
            if (hit != m_parent_handlers.end()) {
                ParentChainAlgo algo = hit->second->GetAlgo();
                auto cv_it = m_job_cvs.find(algo);
                if (cv_it != m_job_cvs.end()) cv_it->second.notify_all();
            }
            return true;
        }
    }
    return false;
}

void MultiMergedStratumServer::NotifyNewParentBlock(const std::string& chain_name) {
    auto it = m_parent_handlers.find(chain_name);
    if (it != m_parent_handlers.end()) {
        ParentChainAlgo algo = it->second->GetAlgo();
        auto cv_it = m_job_cvs.find(algo);
        if (cv_it != m_job_cvs.end()) {
            cv_it->second.notify_all();
        }
    }
}

void MultiMergedStratumServer::NotifyNewWattxBlock() {
    for (auto& [algo, cv] : m_job_cvs) {
        cv.notify_all();
    }
}

// ============================================================================
// Server Threads
// ============================================================================

void MultiMergedStratumServer::AcceptThread(ParentChainAlgo algo) {
    LogPrintf("MultiMergedStratum: Accept thread started for %s\n",
              ParentChainFactory::AlgoToString(algo));

    auto sock_it = m_listen_sockets.find(algo);
    if (sock_it == m_listen_sockets.end()) return;

    int listen_socket = sock_it->second;

    while (m_running.load()) {
        struct pollfd pfd{};
        pfd.fd = listen_socket;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listen_socket, (struct sockaddr*)&client_addr, &addr_len);

        if (client_fd < 0) continue;

        int client_id;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);

            if (m_clients.size() >= static_cast<size_t>(m_config.max_clients_per_algo * m_listen_sockets.size())) {
                LogPrintf("MultiMergedStratum: Max clients reached\n");
                close(client_fd);
                continue;
            }

            client_id = m_next_client_id++;
            auto client = std::make_unique<MultiMergedClient>();
            client->socket_fd = client_fd;
            client->session_id = GenerateSessionId();
            client->algo = algo;
            client->connect_time = GetTime();
            client->last_activity = GetTime();
            m_clients[client_id] = std::move(client);
        }

        m_client_threads.emplace_back(&MultiMergedStratumServer::ClientThread, this, client_id);

        LogPrintf("MultiMergedStratum: Client %d connected (%s)\n",
                  client_id, ParentChainFactory::AlgoToString(algo));
    }
}

void MultiMergedStratumServer::ClientThread(int client_id) {
    char buffer[4096];

    while (m_running.load()) {
        int socket_fd;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it == m_clients.end() || !it->second) break;
            socket_fd = it->second->socket_fd;
        }

        struct pollfd pfd{};
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) break;
        if (ret == 0) continue;

        int bytes = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';

        std::string messages;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it == m_clients.end() || !it->second) break;

            it->second->recv_buffer += buffer;
            it->second->last_activity = GetTime();
            messages = it->second->recv_buffer;
        }

        size_t pos = 0;
        while ((pos = messages.find('\n')) != std::string::npos) {
            std::string message = messages.substr(0, pos);
            messages = messages.substr(pos + 1);

            if (!message.empty()) {
                HandleMessage(client_id, message);
            }
        }

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

void MultiMergedStratumServer::JobThread(ParentChainAlgo algo) {
    LogPrintf("MultiMergedStratum: Job thread started for %s\n",
              ParentChainFactory::AlgoToString(algo));

    while (m_running.load()) {
        CreateJob(algo);

        std::unique_lock<std::mutex> lock(m_job_cv_mutexes[algo]);
        m_job_cvs[algo].wait_for(lock, std::chrono::seconds(m_config.job_timeout_seconds));
    }
}

void MultiMergedStratumServer::ParentPollerThread(const std::string& chain_name) {
    LogPrintf("MultiMergedStratum: Poller thread started for %s\n", chain_name);

    auto handler_it = m_parent_handlers.find(chain_name);
    if (handler_it == m_parent_handlers.end()) return;

    auto& handler = handler_it->second;
    uint64_t last_height = 0;

    while (m_running.load()) {
        std::string hashing_blob, full_template, seed_hash;
        uint64_t height, difficulty;
        ParentCoinbaseData coinbase_data;

        if (handler->GetBlockTemplate(hashing_blob, full_template, seed_hash,
                                       height, difficulty, coinbase_data)) {
            if (height != last_height) {
                LogPrintf("MultiMergedStratum: New %s block at height %lu\n",
                          chain_name, height);
                last_height = height;
                NotifyNewParentBlock(chain_name);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

// ============================================================================
// Protocol Handlers
// ============================================================================

void MultiMergedStratumServer::HandleMessage(int client_id, const std::string& message) {
    std::string method = ParseJsonString(message, "method");
    std::string id = ParseJsonString(message, "id");

    // ── XMRig / Monero protocol ────────────────────────────────────────────────
    if (method == "login") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleLogin(client_id, id, params);
    } else if (method == "submit") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleSubmit(client_id, id, params);
    } else if (method == "getjob") {
        HandleGetJob(client_id, id);
    } else if (method == "keepalived") {
        SendResult(client_id, id, "{\"status\":\"KEEPALIVED\"}");

    // ── Bitcoin stratum protocol ───────────────────────────────────────────────
    } else if (method == "mining.subscribe") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleSubscribe(client_id, id, params);
    } else if (method == "mining.authorize") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleAuthorize(client_id, id, params);
    } else if (method == "mining.submit") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleBtcSubmit(client_id, id, params);
    } else if (method == "mining.extranonce.subscribe") {
        // Acknowledge but we don't dynamically change extranonces
        SendResult(client_id, id, "true");

    // ── Ethash protocol ────────────────────────────────────────────────────────
    } else if (method == "eth_submitLogin") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleEthSubmitLogin(client_id, id, params);
    } else if (method == "eth_getWork") {
        HandleEthGetWork(client_id, id);
    } else if (method == "eth_submitWork") {
        std::vector<std::string> params = ParseJsonArray(message, "params");
        HandleEthSubmitWork(client_id, id, params);

    } else {
        LogPrintf("MultiMergedStratum: Unknown method '%s'\n", method);
        SendError(client_id, id, -1, "Unknown method");
    }
}

// ── Bitcoin stratum helpers ────────────────────────────────────────────────────

std::string MultiMergedStratumServer::MakeExtranonce1(int client_id) {
    char buf[9];
    snprintf(buf, sizeof(buf), "%08x", (uint32_t)client_id);
    return std::string(buf);
}

// Decompose the 80-byte hashing_blob (hex) into Bitcoin stratum mining.notify params.
// Layout: version(4) | prevhash(32) | merkleroot(32) | time(4) | bits(4) | nonce(4)
// Standard stratum encodings: version/nbits/ntime big-endian hex; prevhash as
// 8 uint32 words each byte-reversed (the usual involution miners undo).
//
// coinb1/coinb2 must reassemble — around the miner's extranonce1+extranonce2 —
// the EXACT synthetic aux coinbase whose txid is the mined header's merkle root
// (single-tx block, empty branch). The extranonce region is the 8-byte tail of
// the scriptSig that BuildAuxMergedCoinbase reserves after the MM tag + height.
std::string MultiMergedStratumServer::BuildBtcNotifyParams(
    const MultiAlgoJob& job, bool clean_jobs) const
{
    const std::string& blob = job.hashing_blob;  // 160 hex chars = 80 bytes
    if (blob.size() < 160) return "[]";

    // prevhash: bytes 4-35 of the header, per-4-byte-word byte-swapped
    std::string ph_raw  = blob.substr(8, 64);
    std::string prevhash;
    prevhash.reserve(64);
    for (int w = 0; w < 8; ++w) {
        std::string word = ph_raw.substr(w * 8, 8);
        prevhash += word.substr(6,2) + word.substr(4,2) + word.substr(2,2) + word.substr(0,2);
    }

    // The blob is LE bytes; stratum wants these three fields as BE hex.
    auto be_hex = [&](size_t off) {
        std::string le = blob.substr(off, 8);
        return le.substr(6,2) + le.substr(4,2) + le.substr(2,2) + le.substr(0,2);
    };
    std::string version = be_hex(0);
    std::string ntime   = be_hex(136);
    std::string nbits   = be_hex(144);

    // Serialize the tag-injected coinbase (zero extranonce) and split around its
    // extranonce region. Preferred: the REAL pool-paying coinbase built by
    // GetBlockTemplate (extranonce_offset recorded there). Fallback: the
    // synthetic aux coinbase, whose 1-in/1-out legacy layout is
    // version(4) | vin_count(1) | prevout(36) | script_len(1) | scriptSig | ...
    constexpr size_t EN_SIZE = ParentChainHandlerBase::AUX_COINBASE_EXTRANONCE_SIZE;
    std::string ser_hex;
    size_t en_off = 0;
    const auto& cbd = job.coinbase_data;
    if (!cbd.coinbase_tx.empty() && cbd.extranonce_offset > 0 &&
        cbd.reserve_offset + job.merge_mining_tag.size() <= cbd.coinbase_tx.size() &&
        cbd.extranonce_offset + EN_SIZE <= cbd.coinbase_tx.size()) {
        std::vector<uint8_t> cbv = cbd.coinbase_tx;
        std::memcpy(cbv.data() + cbd.reserve_offset,
                    job.merge_mining_tag.data(), job.merge_mining_tag.size());
        ser_hex = HexStr(cbv);
        en_off = cbd.extranonce_offset;
    } else {
        CMutableTransaction cb = ParentChainHandlerBase::BuildAuxMergedCoinbase(
            job.merge_mining_tag, cbd.parent_height);
        DataStream ds;
        ds << TX_NO_WITNESS(CTransaction(cb));
        ser_hex = HexStr(ds);
        size_t script_len = cb.vin[0].scriptSig.size();
        if (script_len >= 0xFD) return "[]";  // 1-byte script_len varint assumed
        en_off = 4 + 1 + 36 + 1 + script_len - EN_SIZE;
    }
    if ((en_off + EN_SIZE) * 2 > ser_hex.size()) return "[]";

    std::string coinb1 = ser_hex.substr(0, en_off * 2);
    std::string coinb2 = ser_hex.substr((en_off + EN_SIZE) * 2);

    // merkle_branch: empty — our templates include only the coinbase transaction
    std::ostringstream oss;
    oss << "[\"" << job.job_id << "\""
        << ",\"" << prevhash << "\""
        << ",\"" << coinb1 << "\""
        << ",\"" << coinb2 << "\""
        << ",[]"
        << ",\"" << version << "\""
        << ",\"" << nbits << "\""
        << ",\"" << ntime << "\""
        << "," << (clean_jobs ? "true" : "false")
        << "]";
    return oss.str();
}

void MultiMergedStratumServer::SendSetDifficulty(int client_id, double diff) {
    std::ostringstream oss;
    oss << "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[" << diff << "]}\n";
    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::SendMiningNotify(int client_id, const MultiAlgoJob& job, bool clean_jobs) {
    std::string params = BuildBtcNotifyParams(job, clean_jobs);
    std::ostringstream oss;
    oss << "{\"id\":null,\"method\":\"mining.notify\",\"params\":" << params << "}\n";
    SendToClient(client_id, oss.str());
}

// ── Bitcoin stratum: mining.subscribe ─────────────────────────────────────────
void MultiMergedStratumServer::HandleSubscribe(int client_id, const std::string& id,
                                                const std::vector<std::string>& /*params*/) {
    std::string extranonce1 = MakeExtranonce1(client_id);
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end() && it->second) {
            it->second->protocol = StratumProtocol::BTC;
            it->second->extranonce1 = extranonce1;
            it->second->subscribed = true;
        }
    }
    // Response: [[["mining.set_difficulty", sub_id], ["mining.notify", sub_id]], extranonce1, extranonce2_size]
    std::ostringstream oss;
    oss << "{\"id\":" << id
        << ",\"result\":[[["
        << "\"mining.set_difficulty\",\"" << extranonce1 << "\"],"
        << "[\"mining.notify\",\"" << extranonce1 << "\"]]"
        << ",\"" << extranonce1 << "\",4]"
        << ",\"error\":null}\n";
    SendToClient(client_id, oss.str());
}

// ── Bitcoin stratum: mining.authorize ─────────────────────────────────────────
// Login format same as XMRig: "PARENT_ADDR+WTX_ADDR.worker" or "PARENT_ADDR.worker"
void MultiMergedStratumServer::HandleAuthorize(int client_id, const std::string& id,
                                                const std::vector<std::string>& params) {
    std::string login = params.size() >= 1 ? params[0] : "";

    std::string parent_address, wtx_address, worker;
    size_t plus_pos = login.find('+');
    size_t dot_pos  = login.find('.');
    if (plus_pos != std::string::npos) {
        parent_address = login.substr(0, plus_pos);
        if (dot_pos != std::string::npos && dot_pos > plus_pos) {
            wtx_address = login.substr(plus_pos + 1, dot_pos - plus_pos - 1);
            worker      = login.substr(dot_pos + 1);
        } else {
            wtx_address = login.substr(plus_pos + 1);
        }
    } else if (dot_pos != std::string::npos) {
        parent_address = login.substr(0, dot_pos);
        worker         = login.substr(dot_pos + 1);
    } else {
        parent_address = login;
    }
    if (wtx_address.empty()) wtx_address = m_config.wattx_wallet_address;

    ParentChainAlgo algo;
    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) return;
        it->second->wtx_address  = wtx_address;
        it->second->worker_name  = worker.empty() ? "default" : worker;
        it->second->authorized   = true;
        it->second->protocol     = StratumProtocol::BTC;
        algo = it->second->algo;
        auto primary_it = m_algo_primary_chain.find(algo);
        if (primary_it != m_algo_primary_chain.end())
            it->second->chain_addresses[primary_it->second] = parent_address;
    }

    LogPrintf("MultiMergedStratum: BTC authorize client %d (%s, worker: %s)\n",
              client_id, ParentChainFactory::AlgoToString(algo), worker);

    // Confirm authorize
    std::ostringstream ack;
    ack << "{\"id\":" << id << ",\"result\":true,\"error\":null}\n";
    SendToClient(client_id, ack.str());

    // Send initial difficulty + job
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto jit = m_current_jobs.find(algo);
        if (jit != m_current_jobs.end()) job = jit->second;
    }
    if (!job.job_id.empty()) {
        // Advertise the REAL pool share difficulty so standard miners submit
        // shares that actually pass the ValidateShare gate (share_nbits is the
        // regtest testing knob; production uses share_difficulty).
        double diff = static_cast<double>(m_config.share_difficulty);
        if (m_config.share_nbits != 0) {
            arith_uint256 st, d1;
            st.SetCompact(m_config.share_nbits);
            d1.SetCompact(0x1d00ffff);
            if (st != 0) diff = d1.getdouble() / st.getdouble();
        }
        SendSetDifficulty(client_id, diff);
        SendMiningNotify(client_id, job, true);
    }
}

// ── Bitcoin stratum: mining.submit ────────────────────────────────────────────
// params: [worker_name, job_id, extranonce2, ntime, nonce]  (ntime/nonce BE hex)
//
// Unlike the XMRig protocol there is no submitted result hash, so the server
// reconstructs the exact header the miner ground — synthetic aux coinbase with
// this client's extranonce1+extranonce2 spliced in, submitted ntime and nonce —
// and computes the PoW hash itself. That hash feeds the normal ValidateShare
// gate, and the extranonce+ntime ride along so CreateAuxPow rebuilds the same
// coinbase/header for the WATTx proof.
void MultiMergedStratumServer::HandleBtcSubmit(int client_id, const std::string& id,
                                                const std::vector<std::string>& params) {
    if (params.size() < 5) {
        SendError(client_id, id, 20, "Invalid params");
        return;
    }
    const std::string& job_id      = params[1];
    const std::string& extranonce2 = params[2];
    const std::string& ntime_hex   = params[3];
    const std::string& nonce_hex   = params[4];

    if (extranonce2.size() != 8 || ntime_hex.size() != 8 || nonce_hex.size() != 8) {
        SendError(client_id, id, 20, "Invalid params");
        return;
    }

    std::string extranonce1;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) return;
        extranonce1 = it->second->extranonce1;
    }

    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto it = m_jobs.find(job_id);
        if (it == m_jobs.end()) {
            SendError(client_id, id, 21, "Job not found");
            return;
        }
        job = it->second;
    }
    if (!job.coinbase_data.header_snapshot) {
        SendError(client_id, id, 21, "Job not found");
        return;
    }

    auto primary_it = m_algo_primary_chain.find(job.algo);
    auto handler_it = primary_it != m_algo_primary_chain.end()
        ? m_parent_handlers.find(primary_it->second) : m_parent_handlers.end();
    if (handler_it == m_parent_handlers.end()) {
        SendError(client_id, id, 21, "Job not found");
        return;
    }

    uint32_t ntime = static_cast<uint32_t>(strtoul(ntime_hex.c_str(), nullptr, 16));
    uint32_t nonce = static_cast<uint32_t>(strtoul(nonce_hex.c_str(), nullptr, 16));

    // Rebuild the miner's coinbase and header, hash server-side. Same dual path
    // as BuildBtcNotifyParams: real pool-paying coinbase when built, else synthetic.
    std::vector<uint8_t> en = ParseHex(extranonce1 + extranonce2);
    uint256 merkle_root;
    const auto& cbd = job.coinbase_data;
    if (!cbd.coinbase_tx.empty() && cbd.extranonce_offset > 0 &&
        cbd.reserve_offset + job.merge_mining_tag.size() <= cbd.coinbase_tx.size() &&
        cbd.extranonce_offset + en.size() <= cbd.coinbase_tx.size()) {
        std::vector<uint8_t> cbv = cbd.coinbase_tx;
        std::memcpy(cbv.data() + cbd.reserve_offset,
                    job.merge_mining_tag.data(), job.merge_mining_tag.size());
        std::memcpy(cbv.data() + cbd.extranonce_offset, en.data(), en.size());
        merkle_root = Hash(cbv);
    } else {
        CMutableTransaction cb = ParentChainHandlerBase::BuildAuxMergedCoinbase(
            job.merge_mining_tag, cbd.parent_height, &en);
        merkle_root = CTransaction(cb).GetHash();
    }

    std::vector<uint8_t> header = ParentChainHandlerBase::BuildBitcoinHeader(
        static_cast<uint32_t>(job.coinbase_data.parent_version),
        job.coinbase_data.parent_prevhash, merkle_root,
        ntime, job.coinbase_data.parent_bits, nonce);
    uint256 pow_hash = handler_it->second->CalculatePoWHash(header, "");

    // result hex in the byte order ValidateShare memcpys into uint256;
    // nonce as LE hex, matching ValidateShare's first-4-bytes-LE parse
    std::string result_hex = HexStr(std::span<const unsigned char>(pow_hash.begin(), 32));
    std::string nonce_le = nonce_hex.substr(6,2) + nonce_hex.substr(4,2)
                         + nonce_hex.substr(2,2) + nonce_hex.substr(0,2);
    std::string proto_extra = HexStr(en) + ":" + ntime_hex;

    bool valid = ValidateShare(client_id, job_id, nonce_le, result_hex, proto_extra);
    if (valid) {
        std::ostringstream oss;
        oss << "{\"id\":" << id << ",\"result\":true,\"error\":null}\n";
        SendToClient(client_id, oss.str());
    } else {
        SendError(client_id, id, 23, "Low difficulty share");
    }
}

// ── Ethash protocol ────────────────────────────────────────────────────────────
void MultiMergedStratumServer::HandleEthSubmitLogin(int client_id, const std::string& id,
                                                     const std::vector<std::string>& params) {
    std::string login = params.size() >= 1 ? params[0] : "";
    std::string wtx_address;
    std::string worker;
    size_t plus_pos = login.find('+');
    size_t dot_pos  = login.find('.');
    std::string parent_address;
    if (plus_pos != std::string::npos) {
        parent_address = login.substr(0, plus_pos);
        if (dot_pos != std::string::npos && dot_pos > plus_pos) {
            wtx_address = login.substr(plus_pos + 1, dot_pos - plus_pos - 1);
            worker      = login.substr(dot_pos + 1);
        } else {
            wtx_address = login.substr(plus_pos + 1);
        }
    } else if (dot_pos != std::string::npos) {
        parent_address = login.substr(0, dot_pos);
        worker         = login.substr(dot_pos + 1);
    } else {
        parent_address = login;
    }
    if (wtx_address.empty()) wtx_address = m_config.wattx_wallet_address;

    ParentChainAlgo algo;
    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) return;
        it->second->wtx_address = wtx_address;
        it->second->worker_name = worker.empty() ? "default" : worker;
        it->second->authorized  = true;
        it->second->protocol    = StratumProtocol::ETHASH;
        algo = it->second->algo;
        auto primary_it = m_algo_primary_chain.find(algo);
        if (primary_it != m_algo_primary_chain.end())
            it->second->chain_addresses[primary_it->second] = parent_address;
    }

    LogPrintf("MultiMergedStratum: Ethash login client %d (worker: %s)\n", client_id, worker);

    // Confirm login
    std::ostringstream ack;
    ack << "{\"id\":" << id << ",\"result\":true,\"error\":null}\n";
    SendToClient(client_id, ack.str());

    // Send current work
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto jit = m_current_jobs.find(algo);
        if (jit != m_current_jobs.end()) job = jit->second;
    }
    if (!job.job_id.empty()) {
        // Ethash work: [header_hash(blob), seed_hash, target, height]
        std::string target_hex = job.parent_target.GetHex();
        std::ostringstream notify;
        notify << "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
               << "\"" << job.hashing_blob << "\","
               << "\"" << (job.seed_hash.empty() ? "0x" + std::string(64,'0') : job.seed_hash) << "\","
               << "\"0x" << target_hex << "\","
               << job.parent_height
               << "]}\n";
        SendToClient(client_id, notify.str());
    }
}

void MultiMergedStratumServer::HandleEthGetWork(int client_id, const std::string& id) {
    ParentChainAlgo algo;
    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) return;
        algo = it->second->algo;
    }
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto jit = m_current_jobs.find(algo);
        if (jit != m_current_jobs.end()) job = jit->second;
    }
    std::string target_hex = job.parent_target.GetHex();
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"result\":["
        << "\"" << job.hashing_blob << "\","
        << "\"" << (job.seed_hash.empty() ? "0x" + std::string(64,'0') : job.seed_hash) << "\","
        << "\"0x" << target_hex << "\","
        << "\"0x" << std::hex << job.parent_height << std::dec
        << "],\"error\":null}\n";
    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::HandleEthSubmitWork(int client_id, const std::string& id,
                                                    const std::vector<std::string>& params) {
    // params: [nonce, header_hash, mix_digest]
    if (params.size() < 3) { SendError(client_id, id, 20, "Invalid params"); return; }
    const std::string& nonce      = params[0];  // 8-byte nonce hex ("0x..." or raw hex)
    const std::string& header_hash = params[1]; // header_hash == job.hashing_blob for Ethash
    const std::string& mix_hash   = params[2];

    // Look up the Ethash job by hashing_blob (= header_hash sent in eth_getWork)
    std::string job_id;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        for (const auto& [jid, j] : m_jobs) {
            if (j.algo == ParentChainAlgo::ETHASH && j.hashing_blob == header_hash) {
                job_id = jid;
                break;
            }
        }
    }
    if (job_id.empty()) {
        SendToClient(client_id,
            "{\"id\":" + id + ",\"result\":false,\"error\":{\"code\":21,\"message\":\"Job not found\"}}\n");
        return;
    }

    bool valid = ValidateShare(client_id, job_id, nonce, mix_hash);
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"result\":" << (valid ? "true" : "false") << ",\"error\":null}\n";
    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::HandleLogin(int client_id, const std::string& id,
                                            const std::vector<std::string>& params) {
    std::string login, pass, agent;
    if (params.size() >= 1) login = params[0];
    if (params.size() >= 2) pass = params[1];
    if (params.size() >= 3) agent = params[2];

    // Parse addresses: "PARENT_ADDR+WTX_ADDR.WORKER" or "PARENT_ADDR.WORKER"
    std::string parent_address, wtx_address, worker;

    size_t plus_pos = login.find('+');
    size_t dot_pos = login.find('.');

    if (plus_pos != std::string::npos) {
        parent_address = login.substr(0, plus_pos);
        if (dot_pos != std::string::npos && dot_pos > plus_pos) {
            wtx_address = login.substr(plus_pos + 1, dot_pos - plus_pos - 1);
            worker = login.substr(dot_pos + 1);
        } else {
            wtx_address = login.substr(plus_pos + 1);
        }
    } else if (dot_pos != std::string::npos) {
        parent_address = login.substr(0, dot_pos);
        worker = login.substr(dot_pos + 1);
    } else {
        parent_address = login;
    }

    if (wtx_address.empty()) {
        wtx_address = m_config.wattx_wallet_address;
    }

    ParentChainAlgo algo;
    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) return;

        algo = it->second->algo;
        it->second->wtx_address = wtx_address;
        it->second->worker_name = worker.empty() ? "default" : worker;
        it->second->authorized = true;
        it->second->subscribed = true;
        session_id = it->second->session_id;

        // Store parent address for primary chain
        auto primary_it = m_algo_primary_chain.find(algo);
        if (primary_it != m_algo_primary_chain.end()) {
            it->second->chain_addresses[primary_it->second] = parent_address;
        }
    }

    LogPrintf("MultiMergedStratum: Client %d logged in (%s, worker: %s)\n",
              client_id, ParentChainFactory::AlgoToString(algo), worker);

    // Send login response with job
    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto job_it = m_current_jobs.find(algo);
        if (job_it != m_current_jobs.end()) {
            job = job_it->second;
        }
    }

    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"result\":{";
    oss << "\"id\":\"" << session_id << "\",";
    oss << "\"job\":{";
    oss << "\"blob\":\"" << job.hashing_blob << "\",";
    oss << "\"job_id\":\"" << job.job_id << "\",";
    oss << "\"target\":\"" << job.parent_target.GetHex().substr(0, 16) << "\",";
    oss << "\"height\":" << job.parent_height;
    if (!job.seed_hash.empty()) {
        oss << ",\"seed_hash\":\"" << job.seed_hash << "\"";
    }
    oss << "},";
    oss << "\"status\":\"OK\"";
    oss << "}}\n";

    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::HandleSubmit(int client_id, const std::string& id,
                                             const std::vector<std::string>& params) {
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

void MultiMergedStratumServer::HandleGetJob(int client_id, const std::string& id) {
    ParentChainAlgo algo;
    StratumProtocol proto = StratumProtocol::XMRIG;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end() || !it->second) return;
        algo  = it->second->algo;
        proto = it->second->protocol;
    }

    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto job_it = m_current_jobs.find(algo);
        if (job_it != m_current_jobs.end()) {
            job = job_it->second;
        }
    }

    SendJob(client_id, job, proto);
}

// ============================================================================
// Job Management
// ============================================================================

CTransactionRef MultiMergedStratumServer::BuildPayoutCoinbase(
    const std::shared_ptr<interfaces::BlockTemplate>& tmpl)
{
    CTransactionRef base_cb = tmpl ? tmpl->getCoinbaseTx() : nullptr;
    if (!base_cb || base_cb->vout.empty()) return base_cb;

    // Snapshot the miners to pay and their shares (address must decode to a script).
    std::vector<std::pair<CScript, double>> recipients;
    double total_share = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_hashrate_mutex);
        for (const auto& [addr, score] : m_miner_scores) {
            if (score.reward_share <= 0.0) continue;
            CTxDestination dest = DecodeDestination(addr);
            if (!IsValidDestination(dest)) continue;
            recipients.emplace_back(GetScriptForDestination(dest), score.reward_share);
            total_share += score.reward_share;
        }
    }
    // No scored miners yet (or none with a valid address): keep the default coinbase.
    if (recipients.empty() || total_share <= 0.0) return base_cb;

    // The reward output is the largest-value output; every other output (segwit
    // witness commitment OP_RETURN, gas refunds) is preserved verbatim so the block
    // stays valid. Only the reward is split.
    CMutableTransaction cb(*base_cb);
    int reward_idx = -1;
    CAmount reward = 0;
    for (size_t i = 0; i < cb.vout.size(); i++) {
        if (cb.vout[i].nValue > reward) { reward = cb.vout[i].nValue; reward_idx = (int)i; }
    }
    if (reward_idx < 0 || reward <= 0) return base_cb;

    // Build miner outputs summing EXACTLY to `reward` (value conservation — consensus
    // rejects any coinbase over subsidy+fees, so a rounding error can only fail to land,
    // never mint). Assign floor(share/total * reward) to each; the last recipient gets
    // the exact remainder.
    std::vector<CTxOut> payout_outs;
    CAmount assigned = 0;
    for (size_t i = 0; i < recipients.size(); i++) {
        CAmount v;
        if (i + 1 == recipients.size()) {
            v = reward - assigned;                       // exact remainder
        } else {
            v = (CAmount)((recipients[i].second / total_share) * (double)reward);
            if (v < 0) v = 0;
            if (v > reward - assigned) v = reward - assigned;
        }
        assigned += v;
        if (v > 0) payout_outs.emplace_back(v, recipients[i].first);
    }

    // Reassemble vout: miner payout outputs replace the reward output, all other
    // outputs (witness commitment / refunds) kept in place.
    std::vector<CTxOut> new_vout;
    for (size_t i = 0; i < cb.vout.size(); i++) {
        if ((int)i == reward_idx) {
            for (const auto& o : payout_outs) new_vout.push_back(o);
        } else {
            new_vout.push_back(cb.vout[i]);
        }
    }
    cb.vout = std::move(new_vout);
    return MakeTransactionRef(std::move(cb));
}

void MultiMergedStratumServer::CreateJob(ParentChainAlgo algo) {
    // Find primary chain for this algorithm
    auto primary_it = m_algo_primary_chain.find(algo);
    if (primary_it == m_algo_primary_chain.end()) return;

    auto handler_it = m_parent_handlers.find(primary_it->second);
    if (handler_it == m_parent_handlers.end()) return;

    auto& handler = handler_it->second;

    MultiAlgoJob job;
    job.job_id = GenerateJobId();
    job.algo = algo;
    job.created_at = GetTime();

    // Get parent chain template
    if (!handler->GetBlockTemplate(job.hashing_blob, job.full_template, job.seed_hash,
                                    job.parent_height, job.parent_difficulty, job.coinbase_data)) {
        return;
    }

    // Prefer the parent's exact template target; deriving from the integer
    // difficulty floors at diff-1, which makes easy regtest targets unreachable.
    job.parent_target = job.coinbase_data.parent_target.IsNull()
        ? handler->DifficultyToTarget(job.parent_difficulty)
        : job.coinbase_data.parent_target;

    // Get WATTx template
    if (m_wattx_mining) {
        job.wattx_template = m_wattx_mining->createNewBlock();
        if (job.wattx_template) {
            auto header = job.wattx_template->getBlockHeader();
            auto tip = m_wattx_mining->getTip();
            job.wattx_height = tip ? tip->height + 1 : 0;
            job.wattx_bits = header.nBits;

            arith_uint256 target;
            target.SetCompact(job.wattx_bits);
            job.wattx_target = ArithToUint256(target);

            // Create merge mining commitment. It must bind to the SAME block hash
            // consensus will check post-assembly — with AUXPOW_VERSION_FLAG set,
            // nNonce=0, and the merkle root finalized. The template header alone
            // carries a zero merkle root, so ask the template for the canonical hash.
            // Split the block reward among contributing miners by reward_share, and
            // commit to THAT coinbase (frozen in the job) so the aux hash and the
            // submitted block both reflect the payout.
            job.payout_coinbase = BuildPayoutCoinbase(job.wattx_template);
            uint256 wattx_hash = job.wattx_template->getAuxPowBlockHash(job.payout_coinbase);
            job.aux_merkle_root = auxpow::CalcAuxChainMerkleRoot(wattx_hash, handler->GetChainId());
            job.merge_mining_tag = auxpow::BuildMergeMiningTag(job.aux_merkle_root, 0);

            // Rebuild hashing blob with MM tag injected
            job.hashing_blob = handler->BuildHashingBlob(job.coinbase_data, job.merge_mining_tag);
        }
    }

    // Store job
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        m_current_jobs[algo] = job;
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

    // Broadcast to clients
    BroadcastJob(algo, job);

    LogPrintf("MultiMergedStratum: Created %s job %s (parent height: %lu, WTX height: %lu)\n",
              ParentChainFactory::AlgoToString(algo), job.job_id,
              job.parent_height, job.wattx_height);
}

void MultiMergedStratumServer::BroadcastJob(ParentChainAlgo algo, const MultiAlgoJob& job) {
    // Snapshot targets under the lock, then send OUTSIDE it. SendJob ->
    // SendToClient re-locks m_clients_mutex (non-recursive) — holding it
    // here self-deadlocks the JobThread and wedges the whole stratum.
    // Also avoids holding the mutex across blocking socket writes.
    std::vector<std::pair<int, StratumProtocol>> targets;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (const auto& [client_id, client] : m_clients) {
            if (client && client->authorized && client->algo == algo) {
                targets.emplace_back(client_id, client->protocol);
            }
        }
    }
    for (const auto& [client_id, protocol] : targets) {
        SendJob(client_id, job, protocol);
    }
}

bool MultiMergedStratumServer::ValidateShare(int client_id, const std::string& job_id,
                                              const std::string& nonce, const std::string& result,
                                              const std::string& proto_extra) {
    MultiAlgoJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto it = m_jobs.find(job_id);
        if (it == m_jobs.end()) {
            LogPrintf("MultiMergedStratum: Unknown job %s\n", job_id);
            return false;
        }
        job = it->second;
    }

    // Get handler for this job's algorithm
    auto primary_it = m_algo_primary_chain.find(job.algo);
    if (primary_it == m_algo_primary_chain.end()) return false;

    auto handler_it = m_parent_handlers.find(primary_it->second);
    if (handler_it == m_parent_handlers.end()) return false;

    auto& handler = handler_it->second;
    const std::string& chain_name = primary_it->second;

    // Get client's WATTx address for luck calculation
    std::string wtx_address;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end() && it->second) {
            wtx_address = it->second->wtx_address;
        }
    }

    // Parse submitted hash
    std::vector<uint8_t> result_bytes = ParseHex(result);
    if (result_bytes.size() != 32) return false;

    uint256 submitted_hash;
    std::memcpy(submitted_hash.data(), result_bytes.data(), 32);
    arith_uint256 hash_arith = UintToArith256(submitted_hash);

    // Check share difficulty. An explicit share_nbits (testing/regtest knob)
    // overrides the diff-1 floor of DifficultyToTarget so an easy target is usable.
    uint256 share_target;
    if (m_config.share_nbits != 0) {
        arith_uint256 st;
        st.SetCompact(m_config.share_nbits);
        share_target = ArithToUint256(st);
    } else {
        share_target = handler->DifficultyToTarget(m_config.share_difficulty);
    }
    if (hash_arith > UintToArith256(share_target)) {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end() && it->second) {
            it->second->shares_rejected++;
        }
        return false;
    }

    // ========================================================================
    // 50% CAP RULE CHECK
    // ========================================================================
    // Check if miner is already at 50% cap on this chain
    // If so, the share is valid for parent chain but doesn't count toward WATTx scoring
    bool miner_capped = false;
    if (!wtx_address.empty()) {
        miner_capped = IsMinerCappedOnChain(wtx_address, chain_name);
        if (miner_capped) {
            LogPrintf("MultiMergedStratum: Miner %s share on %s exceeds 50%% cap - valid but not scored\n",
                      wtx_address.substr(0, 12) + "...", chain_name);
        }
    }

    // Check parent chain target
    bool meets_parent = (hash_arith <= UintToArith256(job.parent_target));

    // ========================================================================
    // LUCK-ADJUSTED WATTX TARGET
    // ========================================================================
    // Get miner's luck-adjusted target based on their diversification
    // More diversified miners get higher targets (easier to meet)
    uint256 adjusted_wtx_target = job.wattx_target;
    if (!wtx_address.empty()) {
        adjusted_wtx_target = GetAdjustedWtxTarget(job.wattx_target, wtx_address);

        // Log if luck adjustment is significant
        MinerScore score = GetMinerScore(wtx_address);
        if (score.luck_multiplier != 1.0) {
            // Only log occasionally to avoid spam
            static int log_counter = 0;
            if (++log_counter % 100 == 0) {
                LogPrintf("MultiMergedStratum: Miner %s luck: %.2fx (chains: %zu, HHI: %.3f)\n",
                          wtx_address.substr(0, 12) + "...",
                          score.luck_multiplier,
                          score.chains_mined,
                          score.concentration_index);
            }
        }
    }

    // Check WATTx target with luck adjustment
    bool meets_wtx = (hash_arith <= UintToArith256(adjusted_wtx_target));

    // Update statistics. Reaching here means the share already passed the pool
    // difficulty gate, so it counts as an accepted pool SHARE for hashrate estimation
    // and reward scoring — regardless of whether it also happened to meet the (much
    // harder) parent-chain block target. (Previously this was gated on meets_parent,
    // so ordinary shares never registered any hashrate and reward_share stayed 0.)
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end() && it->second) {
            it->second->shares_accepted[chain_name]++;
            m_total_shares[chain_name]++;

            // Record toward WATTx score unless over the 50% cap on this chain
            // (the core of the decentralization rule).
            if (!miner_capped && !wtx_address.empty()) {
                RecordMinerShare(wtx_address, chain_name, m_config.share_difficulty);
            }
            if (meets_wtx) {
                it->second->wtx_blocks_found++;
            }
        }
    }

    // Parse nonce: first 4 bytes (LE) for all algos; Ethash uses full hex via extra_data
    std::vector<uint8_t> nonce_bytes = ParseHex(nonce);
    uint32_t nonce_val = 0;
    if (nonce_bytes.size() >= 4) {
        nonce_val = nonce_bytes[0] | (nonce_bytes[1] << 8) |
                    (nonce_bytes[2] << 16) | (nonce_bytes[3] << 24);
    }

    // Submit to parent chain when share meets parent target
    if (meets_parent) {
        std::string submit_blob;
        ParentChainAlgo algo = handler->GetAlgo();

        if (algo == ParentChainAlgo::RANDOMX) {
            // Monero: full_template is hex-encoded block blob. Inject BOTH the
            // merge-mining tag (at monerod's reserved tx_extra offset — the mined
            // tree root commits to the TAGGED coinbase, so monerod's recomputed
            // PoW only matches with the tag in place) and the winning nonce.
            // Header layout: varint(major) varint(minor) varint(timestamp) 32B(prev_id) 4B(nonce) ...
            std::vector<uint8_t> blob = ParseHex(job.full_template);
            if (!blob.empty()) {
                if (job.coinbase_data.reserve_offset > 0 &&
                    job.coinbase_data.reserve_offset + job.merge_mining_tag.size() <= blob.size()) {
                    std::memcpy(&blob[job.coinbase_data.reserve_offset],
                                job.merge_mining_tag.data(), job.merge_mining_tag.size());
                }
                size_t pos = 0;
                // Read past major, minor, timestamp varints using LEB128
                for (int i = 0; i < 3 && pos < blob.size(); i++) {
                    while (pos < blob.size()) {
                        uint8_t b = blob[pos++];
                        if (!(b & 0x80)) break;
                    }
                }
                pos += 32;  // prev_id
                if (pos + 4 <= blob.size()) {
                    blob[pos+0] = (nonce_val >>  0) & 0xFF;
                    blob[pos+1] = (nonce_val >>  8) & 0xFF;
                    blob[pos+2] = (nonce_val >> 16) & 0xFF;
                    blob[pos+3] = (nonce_val >> 24) & 0xFF;
                    submit_blob = HexStr(blob);
                }
            }
        } else if (algo == ParentChainAlgo::ETHASH) {
            // Ethash: eth_submitWork expects nonce(16 hex) + mix_hash(64 hex)
            std::string nonce_hex = nonce;
            if (nonce_hex.size() >= 2 && nonce_hex.substr(0,2) == "0x")
                nonce_hex = nonce_hex.substr(2);
            while (nonce_hex.size() < 16) nonce_hex = "0" + nonce_hex;
            std::string mix_hex = result;
            if (mix_hex.size() >= 2 && mix_hex.substr(0,2) == "0x")
                mix_hex = mix_hex.substr(2);
            submit_blob = nonce_hex + mix_hex;
        } else {
            // Bitcoin-style (SHA256D, SCRYPT, X11, EQUIHASH, KHEAVYHASH):
            // Full block = 80B header + CompactSize(tx_count) + coinbase + raw_txs

            // Build modified coinbase: merge-mining tag, plus the miner's
            // extranonce + ntime when the share came in over Bitcoin stratum
            // (proto_extra = "extranonce8_hex:ntime8_hex").
            std::vector<uint8_t> modified_cb = job.coinbase_data.coinbase_tx;
            if (job.coinbase_data.reserve_offset > 0 &&
                job.coinbase_data.reserve_offset + job.merge_mining_tag.size() <= modified_cb.size()) {
                std::memcpy(&modified_cb[job.coinbase_data.reserve_offset],
                           job.merge_mining_tag.data(), job.merge_mining_tag.size());
            }
            uint32_t submit_time = job.coinbase_data.parent_time;
            if (size_t colon = proto_extra.find(':'); colon != std::string::npos) {
                std::vector<uint8_t> en = ParseHex(proto_extra.substr(0, colon));
                if (job.coinbase_data.extranonce_offset > 0 &&
                    job.coinbase_data.extranonce_offset + en.size() <= modified_cb.size()) {
                    std::memcpy(&modified_cb[job.coinbase_data.extranonce_offset],
                                en.data(), en.size());
                }
                submit_time = static_cast<uint32_t>(
                    strtoul(proto_extra.substr(colon + 1).c_str(), nullptr, 16));
            }

            // Header must commit to THIS coinbase: with the real pool coinbase +
            // header snapshot, rebuild it exactly as the miner ground it. The
            // legacy BuildBlockHeader path (live header + stale template merkle
            // root) stays only as a fallback for handlers without snapshots.
            std::vector<uint8_t> block;
            if (job.coinbase_data.header_snapshot && !modified_cb.empty() &&
                job.coinbase_data.extranonce_offset > 0) {
                uint256 mr = Hash(modified_cb);  // single-tx block: txid == merkle root
                block = ParentChainHandlerBase::BuildBitcoinHeader(
                    static_cast<uint32_t>(job.coinbase_data.parent_version),
                    job.coinbase_data.parent_prevhash, mr,
                    submit_time, job.coinbase_data.parent_bits, nonce_val);
            } else {
                auto parent_header = handler->BuildBlockHeader(job.coinbase_data, nonce_val);
                if (parent_header) block = parent_header->Serialize();
            }

            if (!block.empty() && !modified_cb.empty()) {
                // CompactSize transaction count
                size_t tx_count = 1 + job.coinbase_data.raw_transactions.size();
                if (tx_count < 0xFD) {
                    block.push_back(static_cast<uint8_t>(tx_count));
                } else {
                    block.push_back(0xFD);
                    block.push_back(tx_count & 0xFF);
                    block.push_back((tx_count >> 8) & 0xFF);
                }

                block.insert(block.end(), modified_cb.begin(), modified_cb.end());
                for (const auto& tx : job.coinbase_data.raw_transactions) {
                    block.insert(block.end(), tx.begin(), tx.end());
                }
                submit_blob = HexStr(block);
            }
        }

        if (!submit_blob.empty()) {
            bool ok = handler->SubmitBlock(submit_blob);
            LogPrintf("MultiMergedStratum: Client %d found %s parent block! %s\n",
                      client_id, chain_name, ok ? "submitted OK" : "submission failed");
            m_total_shares[chain_name + "_blocks"]++;
        } else {
            LogPrintf("MultiMergedStratum: Client %d found %s parent block! (could not build blob)\n",
                      client_id, chain_name);
        }
    }

    // Submit to WATTx if meets target
    if (meets_wtx && job.wattx_template) {
        // Build algo-specific extra_data for CreateAuxPow:
        //   Ethash: "nonce64_hex:mix_hash_hex" — nonce is 8 bytes, result holds mix_hash
        //   Bitcoin stratum: "extranonce8_hex:ntime8_hex" passed in via proto_extra
        //   XMRig: empty
        std::string extra_data;
        if (handler->GetAlgo() == ParentChainAlgo::ETHASH) {
            extra_data = nonce + ":" + result;  // nonce=8-byte hex, result=mix_hash
        } else if (!proto_extra.empty()) {
            extra_data = proto_extra;
        }

        // Create AuxPoW proof with the correct algorithm-specific parent header raw bytes
        CAuxPow auxpow = handler->CreateAuxPow(
            job.wattx_template->getBlockHeader(),
            job.coinbase_data,
            nonce_val,
            job.merge_mining_tag,
            extra_data
        );

        // Verify proof against the SAME canonical block hash the commitment was
        // built over in CreateJob (over the payout-split coinbase), and submit that
        // exact coinbase so the block the network validates pays the miners.
        uint256 wattx_hash = job.wattx_template->getAuxPowBlockHash(job.payout_coinbase);
        if (auxpow.Check(wattx_hash, handler->GetChainId())) {
            auto auxpow_ptr = std::make_shared<CAuxPow>(auxpow);
            auto header = job.wattx_template->getBlockHeader();
            CTransactionRef submit_cb = job.payout_coinbase
                ? job.payout_coinbase : job.wattx_template->getCoinbaseTx();

            bool success = job.wattx_template->submitAuxPowSolution(
                header.nVersion | CAuxPowBlockHeader::AUXPOW_VERSION_FLAG,
                header.nTime,
                0,
                submit_cb,
                auxpow_ptr
            );

            if (success) {
                m_wtx_blocks_found++;
                LogPrintf("MultiMergedStratum: Client %d found WATTx block via %s!\n",
                          client_id, primary_it->second);
            }
        }
    }

    return true;
}

// ============================================================================
// Network Helpers
// ============================================================================

void MultiMergedStratumServer::SendToClient(int client_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    auto it = m_clients.find(client_id);
    if (it == m_clients.end() || !it->second) return;

    send(it->second->socket_fd, message.c_str(), message.length(), MSG_NOSIGNAL);
}

void MultiMergedStratumServer::SendResult(int client_id, const std::string& id, const std::string& result) {
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":" << result << "}\n";
    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::SendError(int client_id, const std::string& id, int code, const std::string& msg) {
    std::ostringstream oss;
    oss << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"error\":{\"code\":" << code
        << ",\"message\":\"" << msg << "\"},\"result\":null}\n";
    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::SendJob(int client_id, const MultiAlgoJob& job,
                                        StratumProtocol proto) {

    if (proto == StratumProtocol::BTC) {
        SendMiningNotify(client_id, job, false);
        return;
    }

    if (proto == StratumProtocol::ETHASH) {
        std::string target_hex = job.parent_target.GetHex();
        std::ostringstream oss;
        oss << "{\"id\":null,\"method\":\"mining.notify\",\"params\":["
            << "\"" << job.hashing_blob << "\","
            << "\"" << (job.seed_hash.empty() ? "0x" + std::string(64,'0') : job.seed_hash) << "\","
            << "\"0x" << target_hex << "\","
            << job.parent_height
            << "]}\n";
        SendToClient(client_id, oss.str());
        return;
    }

    // Default: XMRig / Monero-style "job" push
    std::ostringstream oss;
    oss << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{";
    oss << "\"blob\":\"" << job.hashing_blob << "\",";
    oss << "\"job_id\":\"" << job.job_id << "\",";
    oss << "\"target\":\"" << job.parent_target.GetHex().substr(0, 16) << "\",";
    oss << "\"height\":" << job.parent_height;
    if (!job.seed_hash.empty()) {
        oss << ",\"seed_hash\":\"" << job.seed_hash << "\"";
    }
    oss << "}}\n";
    SendToClient(client_id, oss.str());
}

void MultiMergedStratumServer::DisconnectClient(int client_id) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    auto it = m_clients.find(client_id);
    if (it != m_clients.end()) {
        if (it->second && it->second->socket_fd >= 0) {
            close(it->second->socket_fd);
        }
        m_clients.erase(it);
        LogPrintf("MultiMergedStratum: Client %d disconnected\n", client_id);
    }
}

std::string MultiMergedStratumServer::GenerateJobId() {
    uint64_t counter = m_job_counter++;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << counter;
    return oss.str();
}

std::string MultiMergedStratumServer::GenerateSessionId() {
    unsigned char rand_bytes[16];
    GetRandBytes(rand_bytes);
    return HexStr(rand_bytes);
}

// ============================================================================
// Hashrate Tracking & Nethash-Based Scoring
// ============================================================================
//
// INCENTIVE MECHANISM:
// Miners earn points based on their % contribution to each chain's nethash.
// Higher contribution % = more points = more WATTx rewards.
//
// This incentivizes miners to mine chains that NEED hashrate:
//   - Mining 5% of SmallCoin = 5.0 points
//   - Mining 0.001% of Bitcoin = 0.001 points
//
// Formula: MinerScore = Σ (miner_hashrate_on_chain / chain_nethash) * 100
// ============================================================================

void MultiMergedStratumServer::HashrateUpdateThread() {
    while (m_running.load()) {
        UpdateCoinHashrates();
        UpdateMinerHashrates();
        RecalculateMinerScores();

        // Sleep for update interval
        std::this_thread::sleep_for(
            std::chrono::seconds(m_config.hashrate_update_interval));
    }
}

void MultiMergedStratumServer::UpdateCoinHashrates() {
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    for (auto& [name, handler] : m_parent_handlers) {
        auto& stats = m_coin_stats[name];
        stats.coin_name = name;
        stats.algo = handler->GetAlgo();

        // Get network stats from daemon
        std::string hashing_blob, full_template, seed_hash;
        uint64_t height, difficulty;
        ParentCoinbaseData coinbase;

        if (handler->GetBlockTemplate(hashing_blob, full_template, seed_hash,
                                       height, difficulty, coinbase)) {
            stats.network_difficulty = difficulty;

            // Estimate network hashrate from difficulty
            // hashrate ≈ difficulty * 2^32 / block_time
            // Using 600 seconds (10 min) as default block time
            uint64_t block_time = 600;
            stats.network_hashrate = (difficulty * 0x100000000ULL) / block_time;
        }

        // Calculate pool hashrate from recent shares
        uint64_t time_window = 600;  // 10 minute window
        uint64_t recent_shares = m_total_shares[name].load();
        stats.pool_hashrate = (recent_shares * m_config.share_difficulty * 0x100000000ULL) / time_window;
        stats.pool_shares = recent_shares;

        // Calculate pool's % of network hashrate
        if (stats.network_hashrate > 0) {
            stats.pool_nethash_percent = (static_cast<double>(stats.pool_hashrate) /
                                          static_cast<double>(stats.network_hashrate)) * 100.0;
        } else {
            stats.pool_nethash_percent = 0.0;
        }

        stats.last_update = GetTime();

        LogPrintf("MultiMergedStratum: %s - NetHash: %lu H/s, PoolHash: %lu H/s, Pool%%: %.4f%%\n",
                  name, stats.network_hashrate, stats.pool_hashrate, stats.pool_nethash_percent);
    }
}

void MultiMergedStratumServer::UpdateMinerHashrates() {
    std::lock_guard<std::mutex> lock_clients(m_clients_mutex);
    std::lock_guard<std::mutex> lock_hashrate(m_hashrate_mutex);

    // Clear old miner hashrates
    for (auto& [coin_name, stats] : m_coin_stats) {
        stats.miner_hashrates.clear();
    }

    // Aggregate miner hashrates from client shares
    uint64_t time_window = 600;  // 10 minute window

    for (const auto& [client_id, client] : m_clients) {
        if (!client || client->wtx_address.empty()) continue;

        for (const auto& [coin_name, shares] : client->shares_accepted) {
            auto stats_it = m_coin_stats.find(coin_name);
            if (stats_it == m_coin_stats.end()) continue;

            // Estimate miner's hashrate: (shares * share_diff * 2^32) / time
            uint64_t miner_hashrate = (shares * m_config.share_difficulty * 0x100000000ULL) / time_window;
            stats_it->second.miner_hashrates[client->wtx_address] += miner_hashrate;
        }
    }
}

void MultiMergedStratumServer::RecalculateMinerScores() {
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    // Clear old scores
    m_miner_scores.clear();

    // Collect all unique miners
    std::set<std::string> all_miners;
    for (const auto& [coin_name, stats] : m_coin_stats) {
        for (const auto& [miner, hashrate] : stats.miner_hashrates) {
            all_miners.insert(miner);
        }
    }

    // Calculate scores for each miner
    double total_all_scores = 0.0;

    for (const auto& miner_addr : all_miners) {
        MinerScore score;
        score.wtx_address = miner_addr;
        score.total_score = 0.0;
        score.chains_mined = 0;

        // For each chain, calculate miner's % of nethash
        for (const auto& [coin_name, stats] : m_coin_stats) {
            auto it = stats.miner_hashrates.find(miner_addr);
            if (it == stats.miner_hashrates.end()) continue;

            uint64_t miner_hashrate = it->second;
            double nethash_percent_raw = 0.0;

            if (stats.network_hashrate > 0) {
                // Miner's contribution as % of network (RAW, uncapped). This is what
                // rewards securing SMALLER networks: a big % of a small chain's nethash
                // scores far more than a tiny % of a large one.
                nethash_percent_raw = (static_cast<double>(miner_hashrate) /
                                       static_cast<double>(stats.network_hashrate)) * 100.0;
            } else if (stats.pool_hashrate > 0) {
                // Network hashrate unknown/unmeasurable (e.g. the parent daemon reports
                // no usable difficulty). Fall back to the miner's share of the POOL's
                // hashrate on this chain so contributions still earn a fair, non-zero
                // reward instead of nothing. (Loses the small-network bonus, which needs
                // a real nethash to compute, but keeps payouts fair and functional.)
                nethash_percent_raw = (static_cast<double>(miner_hashrate) /
                                       static_cast<double>(stats.pool_hashrate)) * 100.0;
            }

            // Store raw percentage
            score.chain_contributions_raw[coin_name] = nethash_percent_raw;

            // Apply 50% cap for scoring purposes
            // Shares beyond 50% don't count toward WATTx score (decentralization incentive)
            double nethash_percent_capped = std::min(nethash_percent_raw, MAX_NETHASH_PERCENT_PER_CHAIN);

            if (nethash_percent_raw > MAX_NETHASH_PERCENT_PER_CHAIN) {
                LogPrintf("MultiMergedStratum: Miner %s CAPPED on %s (%.2f%% -> %.2f%%)\n",
                          miner_addr.substr(0, 12) + "...", coin_name,
                          nethash_percent_raw, nethash_percent_capped);
            }

            score.chain_contributions[coin_name] = nethash_percent_capped;
            score.total_score += nethash_percent_capped;  // Sum of CAPPED chain contributions
            score.chains_mined++;
        }

        // Calculate diversification luck multiplier
        score.luck_multiplier = CalculateLuckMultiplier(score);

        total_all_scores += score.total_score;
        m_miner_scores[miner_addr] = score;
    }

    // Normalize to get reward shares (% of block reward each miner gets)
    if (total_all_scores > 0.0) {
        for (auto& [miner_addr, score] : m_miner_scores) {
            score.reward_share = score.total_score / total_all_scores;

            LogPrintf("MultiMergedStratum: Miner %s - Score: %.4f, Reward%%: %.4f%%, Luck: %.2fx, Chains: %zu, HHI: %.3f\n",
                      miner_addr.substr(0, 12) + "...",
                      score.total_score,
                      score.reward_share * 100.0,
                      score.luck_multiplier,
                      score.chains_mined,
                      score.concentration_index);
        }
    }
}

void MultiMergedStratumServer::RecordMinerShare(const std::string& wtx_address,
                                                 const std::string& coin_name,
                                                 uint64_t difficulty) {
    // Called when a miner submits a valid share
    // The share counts toward their hashrate on that chain
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    auto stats_it = m_coin_stats.find(coin_name);
    if (stats_it != m_coin_stats.end()) {
        // Increment their share-based hashrate contribution
        // This gets converted to hashrate in UpdateMinerHashrates()
        stats_it->second.miner_hashrates[wtx_address] += difficulty;
    }
}

MinerScore MultiMergedStratumServer::GetMinerScore(const std::string& wtx_address) const {
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    auto it = m_miner_scores.find(wtx_address);
    if (it != m_miner_scores.end()) {
        return it->second;
    }
    // Return default score for unknown miner
    MinerScore default_score;
    default_score.wtx_address = wtx_address;
    default_score.total_score = 0.0;
    default_score.reward_share = 0.0;
    default_score.luck_multiplier = 1.0;  // Default luck for new miners
    default_score.chains_mined = 0;
    default_score.concentration_index = 1.0;
    return default_score;
}

std::vector<MinerScore> MultiMergedStratumServer::GetAllMinerScores() const {
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    std::vector<MinerScore> result;
    result.reserve(m_miner_scores.size());

    for (const auto& [addr, score] : m_miner_scores) {
        result.push_back(score);
    }

    // Sort by score descending
    std::sort(result.begin(), result.end(),
              [](const MinerScore& a, const MinerScore& b) {
                  return a.total_score > b.total_score;
              });

    return result;
}

double MultiMergedStratumServer::GetTotalMinerScores() const {
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    double total = 0.0;
    for (const auto& [addr, score] : m_miner_scores) {
        total += score.total_score;
    }
    return total;
}

// ============================================================================
// DECENTRALIZATION MECHANISMS
// ============================================================================
//
// These functions implement the hashrate decentralization incentives:
//
// 1. 50% CAP RULE:
//    No miner can benefit from contributing >50% of any chain's nethash.
//    This prevents hashrate centralization on individual chains.
//
// 2. LUCK WEIGHTING:
//    Miners who diversify across multiple chains get better WATTx luck.
//    Uses Herfindahl-Hirschman Index (HHI) to measure concentration.
//    - HHI near 1.0 = concentrated on one chain = low luck
//    - HHI near 0.0 = spread across many chains = high luck
//
// ============================================================================

bool MultiMergedStratumServer::IsMinerCappedOnChain(const std::string& wtx_address,
                                                     const std::string& coin_name) const {
    return GetMinerNethashPercent(wtx_address, coin_name) >= MAX_NETHASH_PERCENT_PER_CHAIN;
}

double MultiMergedStratumServer::GetMinerNethashPercent(const std::string& wtx_address,
                                                         const std::string& coin_name) const {
    std::lock_guard<std::mutex> lock(m_hashrate_mutex);

    auto stats_it = m_coin_stats.find(coin_name);
    if (stats_it == m_coin_stats.end()) return 0.0;

    const auto& stats = stats_it->second;
    auto miner_it = stats.miner_hashrates.find(wtx_address);
    if (miner_it == stats.miner_hashrates.end()) return 0.0;

    if (stats.network_hashrate == 0) return 0.0;

    return (static_cast<double>(miner_it->second) /
            static_cast<double>(stats.network_hashrate)) * 100.0;
}

double MultiMergedStratumServer::CalculateLuckMultiplier(const MinerScore& score) {
    // Luck is based on diversification - more chains = better luck
    //
    // We use the Herfindahl-Hirschman Index (HHI) to measure concentration:
    //   HHI = Σ (share_i)^2 where share_i = chain_contribution / total_contribution
    //
    // HHI ranges from 1/N (perfectly diversified across N chains) to 1.0 (all on one chain)
    //
    // Luck multiplier is inversely related to HHI:
    //   - HHI = 1.0 (one chain only) -> luck = MIN_LUCK_MULTIPLIER (0.5x = harder)
    //   - HHI = 0.1 (10 equal chains) -> luck = MAX_LUCK_MULTIPLIER (3.0x = easier)

    if (score.chain_contributions.empty() || score.total_score <= 0.0) {
        return 1.0;  // Default luck for new miners
    }

    // Calculate HHI using CAPPED contributions
    double sum_squared = 0.0;
    for (const auto& [chain, percent] : score.chain_contributions) {
        double share = percent / score.total_score;  // Normalize to get market share
        sum_squared += share * share;
    }

    // HHI is now in range [1/N, 1.0]
    double hhi = sum_squared;

    // Store for logging
    const_cast<MinerScore&>(score).concentration_index = hhi;

    // Convert HHI to luck multiplier
    // We use inverse square root for smooth scaling:
    //   luck = 1 / sqrt(hhi)
    //
    // This gives:
    //   HHI = 1.0  -> luck = 1.0
    //   HHI = 0.25 -> luck = 2.0
    //   HHI = 0.11 -> luck = 3.0
    //
    // Then we shift and scale to our desired range

    double raw_luck = 1.0 / std::sqrt(hhi);

    // Scale to our range [MIN_LUCK_MULTIPLIER, MAX_LUCK_MULTIPLIER]
    // raw_luck of 1.0 (concentrated) -> MIN_LUCK_MULTIPLIER
    // raw_luck of 3.0+ (diversified) -> MAX_LUCK_MULTIPLIER
    double luck = MIN_LUCK_MULTIPLIER +
                  (raw_luck - 1.0) * (MAX_LUCK_MULTIPLIER - MIN_LUCK_MULTIPLIER) / 2.0;

    // Clamp to valid range
    luck = std::max(MIN_LUCK_MULTIPLIER, std::min(MAX_LUCK_MULTIPLIER, luck));

    return luck;
}

uint256 MultiMergedStratumServer::GetAdjustedWtxTarget(const uint256& base_target,
                                                        const std::string& wtx_address) const {
    // Get miner's luck multiplier
    MinerScore score = GetMinerScore(wtx_address);

    if (score.luck_multiplier <= 0.0 || score.luck_multiplier == 1.0) {
        return base_target;  // No adjustment needed
    }

    // Multiply target by luck multiplier
    // Higher luck = higher target = easier to find blocks
    arith_uint256 target = UintToArith256(base_target);

    // Scale by luck multiplier (using fixed-point math to avoid precision loss)
    // luck_multiplier is in range [0.5, 3.0]
    uint64_t luck_scaled = static_cast<uint64_t>(score.luck_multiplier * 1000000.0);
    target = (target * luck_scaled) / 1000000;

    // The adjusted target may never be EASIER than the WATTx block's own target.
    // Consensus validates the AuxPoW parent PoW against the block's nBits (== base_target),
    // so any share easier than base_target would pass the stratum gate yet be rejected as a
    // block — the miner would find "blocks" that never land. (The old code clamped to a
    // hardcoded Bitcoin-mainnet constant 0x1d00ffff, which on regtest and any chain whose
    // powLimit is easier than mainnet is actually HARDER than the real target: it silently
    // made WATTx blocks unfindable the instant a miner's luck multiplier moved off 1.0.)
    // A luck penalty (luck < 1.0) legitimately makes the target harder and is preserved.
    arith_uint256 base = UintToArith256(base_target);
    if (target > base) {
        target = base;
    }

    return ArithToUint256(target);
}

}  // namespace merged_stratum
