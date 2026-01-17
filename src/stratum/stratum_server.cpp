// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stratum/stratum_server.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <node/randomx_miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace stratum {

// Global instance
static std::unique_ptr<StratumServer> g_stratum_server;

StratumServer& GetStratumServer() {
    if (!g_stratum_server) {
        g_stratum_server = std::make_unique<StratumServer>();
    }
    return *g_stratum_server;
}

StratumServer::StratumServer() = default;

StratumServer::~StratumServer() {
    Stop();
}

bool StratumServer::Start(const StratumConfig& config, interfaces::Mining* mining) {
    if (m_running.load()) {
        LogPrintf("Stratum: Server already running\n");
        return false;
    }

    m_config = config;
    m_mining = mining;

    // Create listening socket
    m_listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_listen_socket < 0) {
        LogPrintf("Stratum: Failed to create socket\n");
        return false;
    }

    // Set socket options for address reuse
    int opt = 1;
    setsockopt(m_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(m_listen_socket, SOL_SOCKET, SO_REUSEPORT, (const char*)&opt, sizeof(opt));
#endif

    // Bind to address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.port);

    if (config.bind_address == "0.0.0.0") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, config.bind_address.c_str(), &server_addr.sin_addr);
    }

    if (bind(m_listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LogPrintf("Stratum: Failed to bind to port %d\n", config.port);
#ifdef WIN32
        closesocket(m_listen_socket);
#else
        close(m_listen_socket);
#endif
        m_listen_socket = -1;
        return false;
    }

    // Start listening
    if (listen(m_listen_socket, config.max_clients) < 0) {
        LogPrintf("Stratum: Failed to listen\n");
#ifdef WIN32
        closesocket(m_listen_socket);
#else
        close(m_listen_socket);
#endif
        m_listen_socket = -1;
        return false;
    }

    m_running.store(true);

    // Start accept thread
    m_accept_thread = std::thread(&StratumServer::AcceptThread, this);

    // Start job generation thread
    m_job_thread = std::thread(&StratumServer::JobThread, this);

    LogPrintf("Stratum: Server started on %s:%d\n", config.bind_address, config.port);
    return true;
}

void StratumServer::Stop() {
    if (!m_running.load()) return;

    m_running.store(false);

    // Close listening socket to wake up accept thread
    if (m_listen_socket >= 0) {
#ifdef WIN32
        closesocket(m_listen_socket);
#else
        close(m_listen_socket);
#endif
        m_listen_socket = -1;
    }

    // Wake up job thread
    m_job_cv.notify_all();

    // Wait for threads
    if (m_accept_thread.joinable()) m_accept_thread.join();
    if (m_job_thread.joinable()) m_job_thread.join();
    for (auto& t : m_client_threads) {
        if (t.joinable()) t.join();
    }
    m_client_threads.clear();

    // Disconnect all clients
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (auto& [id, client] : m_clients) {
            if (client->socket_fd >= 0) {
#ifdef WIN32
                closesocket(client->socket_fd);
#else
                close(client->socket_fd);
#endif
            }
        }
        m_clients.clear();
    }

    LogPrintf("Stratum: Server stopped\n");
}

size_t StratumServer::GetClientCount() const {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    return m_clients.size();
}

void StratumServer::AcceptThread() {
    LogPrintf("Stratum: Accept thread started\n");

    while (m_running.load()) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_socket = accept(m_listen_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (m_running.load()) {
                LogPrintf("Stratum: Accept failed\n");
            }
            continue;
        }

        // Set non-blocking
#ifdef WIN32
        u_long mode = 1;
        ioctlsocket(client_socket, FIONBIO, &mode);
#else
        fcntl(client_socket, F_SETFL, O_NONBLOCK);
#endif

        // Create client
        int client_id;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            client_id = m_next_client_id++;
            auto client = std::make_unique<StratumClient>();
            client->socket_fd = client_socket;
            client->session_id = GenerateSessionId();
            client->connect_time = GetTime();
            client->last_activity = client->connect_time;
            m_clients[client_id] = std::move(client);
        }

        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, addr_str, sizeof(addr_str));
        LogPrintf("Stratum: Client %d connected from %s\n", client_id, addr_str);

        // Start client handler thread
        m_client_threads.emplace_back(&StratumServer::ClientThread, this, client_id);
    }

    LogPrintf("Stratum: Accept thread stopped\n");
}

void StratumServer::ClientThread(int client_id) {
    char buffer[4096];

    while (m_running.load()) {
        int socket_fd;
        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            auto it = m_clients.find(client_id);
            if (it == m_clients.end()) break;
            socket_fd = it->second->socket_fd;
        }

        // Read data
        ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';

            // Collect complete messages while holding the lock
            std::vector<std::string> messages;
            {
                std::lock_guard<std::mutex> lock(m_clients_mutex);
                auto it = m_clients.find(client_id);
                if (it == m_clients.end()) break;

                it->second->recv_buffer += buffer;
                it->second->last_activity = GetTime();

                // Extract complete messages (newline-delimited JSON)
                size_t pos;
                while ((pos = it->second->recv_buffer.find('\n')) != std::string::npos) {
                    std::string message = it->second->recv_buffer.substr(0, pos);
                    it->second->recv_buffer.erase(0, pos + 1);
                    if (!message.empty()) {
                        messages.push_back(message);
                    }
                }
            }

            // Process messages without holding the lock to avoid deadlock
            for (const auto& message : messages) {
                HandleMessage(client_id, message);
            }
        } else if (bytes_read == 0) {
            // Connection closed
            LogPrintf("Stratum: Client %d disconnected\n", client_id);
            break;
        } else {
#ifdef WIN32
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                break;
            }
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }
#endif
            // No data available, sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    DisconnectClient(client_id);
}

void StratumServer::JobThread() {
    LogPrintf("Stratum: Job thread started\n");

    while (m_running.load()) {
        // Create new job
        CreateNewJob();

        // Wait for new block or timeout
        std::unique_lock<std::mutex> lock(m_job_cv_mutex);
        m_job_cv.wait_for(lock, std::chrono::seconds(m_config.job_timeout_seconds),
                          [this] { return !m_running.load(); });
    }

    LogPrintf("Stratum: Job thread stopped\n");
}

void StratumServer::HandleMessage(int client_id, const std::string& message) {
    try {
        UniValue request;
        if (!request.read(message)) {
            LogPrintf("Stratum: Invalid JSON from client %d\n", client_id);
            return;
        }

        std::string method;
        std::string id = "null";
        std::vector<std::string> params;

        if (request.exists("method")) {
            method = request["method"].get_str();
        }
        if (request.exists("id") && !request["id"].isNull()) {
            if (request["id"].isStr()) {
                id = "\"" + request["id"].get_str() + "\"";
            } else {
                id = request["id"].write();
            }
        }
        if (request.exists("params")) {
            if (request["params"].isArray()) {
                const UniValue& arr = request["params"];
                for (size_t i = 0; i < arr.size(); i++) {
                    if (arr[i].isStr()) {
                        params.push_back(arr[i].get_str());
                    } else {
                        params.push_back(arr[i].write());
                    }
                }
            } else if (request["params"].isObject()) {
                // XMRig sends params as JSON object, store as single JSON string
                params.push_back(request["params"].write());
            }
        }

        LogPrintf("Stratum: Client %d method=%s\n", client_id, method);

        if (method == "mining.subscribe") {
            HandleSubscribe(client_id, id, params);
        } else if (method == "mining.authorize") {
            HandleAuthorize(client_id, id, params);
        } else if (method == "mining.submit" || method == "submit") {
            // XMRig uses "submit" without "mining." prefix
            HandleSubmit(client_id, id, params);
        } else if (method == "login" || method == "getjob") {
            // XMRig-style login
            HandleGetJob(client_id, id, params);
        } else {
            LogPrintf("Stratum: Unknown method: %s\n", method);
            SendError(client_id, id, -1, "Unknown method");
        }
    } catch (const std::exception& e) {
        LogPrintf("Stratum: Error handling message: %s\n", e.what());
    }
}

void StratumServer::HandleSubscribe(int client_id, const std::string& id, const std::vector<std::string>& params) {
    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end()) return;
        it->second->subscribed = true;
        session_id = it->second->session_id;
    }

    // Send subscription response
    // Format: {"id":1,"result":[[["mining.notify","session_id"]],"extranonce1","extranonce2_size"],"error":null}
    std::ostringstream response;
    response << "{\"id\":" << id << ",\"result\":[[";
    response << "[\"mining.notify\",\"" << session_id << "\"]";
    response << "],\"" << session_id.substr(0, 8) << "\",4],\"error\":null}\n";

    SendToClient(client_id, response.str());
    LogPrintf("Stratum: Client %d subscribed\n", client_id);
}

void StratumServer::HandleAuthorize(int client_id, const std::string& id, const std::vector<std::string>& params) {
    std::string worker = params.size() > 0 ? params[0] : "";
    std::string password = params.size() > 1 ? params[1] : "";

    // Parse worker name (format: wallet_address.worker_name or just wallet_address)
    std::string wallet_address = worker;
    std::string worker_name = "default";

    size_t dot_pos = worker.find('.');
    if (dot_pos != std::string::npos) {
        wallet_address = worker.substr(0, dot_pos);
        worker_name = worker.substr(dot_pos + 1);
    }

    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end()) return;
        it->second->authorized = true;
        it->second->wallet_address = wallet_address;
        it->second->worker_name = worker_name;
    }

    // Send authorization success
    std::ostringstream response;
    response << "{\"id\":" << id << ",\"result\":true,\"error\":null}\n";
    SendToClient(client_id, response.str());

    LogPrintf("Stratum: Client %d authorized as %s (%s)\n", client_id, wallet_address, worker_name);

    // Send current job
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        if (!m_current_job.job_id.empty()) {
            SendJob(client_id, m_current_job);
        }
    }
}

void StratumServer::HandleGetJob(int client_id, const std::string& id, const std::vector<std::string>& params) {
    // XMRig-style login/getjob - combined subscribe+authorize+getjob
    LogPrintf("Stratum: HandleGetJob called for client %d, id=%s, params.size=%d\n", client_id, id, params.size());
    for (size_t i = 0; i < params.size(); i++) {
        LogPrintf("Stratum: params[%d]=%s\n", i, params[i].substr(0, 200));
    }

    std::string login;
    std::string pass;

    // Try to parse XMRig format
    if (!params.empty()) {
        try {
            UniValue p;
            if (p.read(params[0])) {
                if (p.exists("login")) login = p["login"].get_str();
                if (p.exists("pass")) pass = p["pass"].get_str();
            }
        } catch (...) {
            login = params[0];
        }
    }

    LogPrintf("Stratum: HandleGetJob - parsed login=%s\n", login.empty() ? "(empty)" : login.substr(0, 50));

    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it == m_clients.end()) {
            LogPrintf("Stratum: HandleGetJob - client %d not found!\n", client_id);
            return;
        }
        it->second->subscribed = true;
        it->second->authorized = true;
        it->second->wallet_address = login.empty() ? m_config.default_wallet : login;
        it->second->worker_name = "xmrig";
        session_id = it->second->session_id;
        LogPrintf("Stratum: HandleGetJob - client %d configured, session_id=%s\n", client_id, session_id.substr(0, 16));
    }

    // Build XMRig-style response with job
    StratumJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        job = m_current_job;
    }
    LogPrintf("Stratum: HandleGetJob - got job %s at height %d, blob_size=%d\n", job.job_id, job.height, job.blob.size());

    std::ostringstream response;
    response << "{\"id\":" << id << ",\"jsonrpc\":\"2.0\",\"result\":{";
    response << "\"id\":\"" << session_id << "\",";
    response << "\"job\":{";
    response << "\"blob\":\"" << job.blob << "\",";
    response << "\"job_id\":\"" << job.job_id << "\",";
    response << "\"target\":\"" << job.target << "\",";
    response << "\"algo\":\"rx/0\",";  // RandomX algorithm
    response << "\"height\":" << job.height << ",";
    response << "\"seed_hash\":\"" << job.seed_hash << "\"";
    response << "},";
    response << "\"status\":\"OK\"";
    response << "},\"error\":null}\n";

    std::string resp = response.str();
    LogPrintf("Stratum: HandleGetJob - sending response (%d bytes): %s\n", resp.size(), resp.substr(0, 300));
    SendToClient(client_id, resp);
    LogPrintf("Stratum: Client %d logged in (XMRig style)\n", client_id);
}

void StratumServer::HandleSubmit(int client_id, const std::string& id, const std::vector<std::string>& params) {
    // Standard stratum: ["worker", "job_id", "extranonce2", "ntime", "nonce"]
    // XMRig style: {"id":"...", "job_id":"...", "nonce":"...", "result":"..."}

    std::string job_id;
    std::string nonce;
    std::string result;

    if (params.size() >= 5) {
        // Standard stratum format
        job_id = params[1];
        nonce = params[4];
    } else if (params.size() >= 1) {
        // Try XMRig JSON format
        try {
            UniValue p;
            if (p.read(params[0])) {
                if (p.exists("job_id")) job_id = p["job_id"].get_str();
                if (p.exists("nonce")) nonce = p["nonce"].get_str();
                if (p.exists("result")) result = p["result"].get_str();
            }
        } catch (...) {}
    }

    if (job_id.empty() || nonce.empty()) {
        SendError(client_id, id, 20, "Invalid submit format");
        return;
    }

    bool accepted = ValidateAndSubmitShare(client_id, job_id, nonce, result);

    if (accepted) {
        std::ostringstream response;
        response << "{\"id\":" << id << ",\"result\":{\"status\":\"OK\"},\"error\":null}\n";
        SendToClient(client_id, response.str());

        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end()) {
            it->second->shares_accepted++;
        }
        m_total_shares_accepted++;
    } else {
        SendError(client_id, id, 23, "Invalid share");

        std::lock_guard<std::mutex> lock(m_clients_mutex);
        auto it = m_clients.find(client_id);
        if (it != m_clients.end()) {
            it->second->shares_rejected++;
        }
        m_total_shares_rejected++;
    }
}

void StratumServer::CreateNewJob() {
    if (!m_mining) return;

    try {
        // Get block template
        auto block_template = m_mining->createNewBlock();
        if (!block_template) {
            LogPrintf("Stratum: Failed to create block template\n");
            return;
        }

        CBlock block = block_template->getBlock();

        StratumJob job;
        job.job_id = GenerateJobId();
        job.timestamp = block.nTime;
        job.bits = block.nBits;
        job.prev_hash = block.hashPrevBlock.GetHex();

        // Get height from chain
        auto tip = m_mining->getTip();
        job.height = tip ? tip->height + 1 : 1;

        // Store the block template for later submission
        job.block_template = std::shared_ptr<interfaces::BlockTemplate>(block_template.release());

        // Create XMRig-compatible blob (76 bytes for Monero format)
        // XMRig expects nonce at bytes 39-42, we'll use this as a nonce generator
        // Structure:
        // - bytes 0-34: first 35 bytes of block header hash
        // - bytes 35-38: timestamp (4 bytes)
        // - bytes 39-42: nonce placeholder (XMRig modifies here)
        // - bytes 43-75: remaining 33 bytes of data

        // Get the real serialized header for validation
        auto fullHeader = node::RandomXMiner::SerializeBlockHeader(block);

        // Create Monero-compatible blob for XMRig
        std::vector<unsigned char> miningBlob(76, 0);

        // Fill with deterministic data derived from block
        // Use prevBlock hash (32 bytes) for first part
        std::memcpy(miningBlob.data(), block.hashPrevBlock.data(), 32);

        // Bytes 32-34: version (3 bytes)
        miningBlob[32] = block.nVersion & 0xFF;
        miningBlob[33] = (block.nVersion >> 8) & 0xFF;
        miningBlob[34] = (block.nVersion >> 16) & 0xFF;

        // Bytes 35-38: timestamp
        miningBlob[35] = block.nTime & 0xFF;
        miningBlob[36] = (block.nTime >> 8) & 0xFF;
        miningBlob[37] = (block.nTime >> 16) & 0xFF;
        miningBlob[38] = (block.nTime >> 24) & 0xFF;

        // Bytes 39-42: nonce placeholder (will be modified by XMRig)
        miningBlob[39] = 0;
        miningBlob[40] = 0;
        miningBlob[41] = 0;
        miningBlob[42] = 0;

        // Bytes 43-75: merkle root (first 33 bytes)
        std::memcpy(miningBlob.data() + 43, block.hashMerkleRoot.data(), 32);
        miningBlob[75] = block.nBits & 0xFF;

        job.blob = HexStr(miningBlob);

        // Calculate target from bits
        arith_uint256 target;
        target.SetCompact(block.nBits);

        // XMRig target format:
        // - 4-8 bytes in little-endian hex
        // - Represents the threshold: if hash (as 256-bit LE number) <= target, share is valid
        // - Lower target = higher difficulty
        //
        // Our target is a 256-bit number with many leading zeros.
        // nBits format: 0xNNXXXXXX where NN is exponent, XXXXXX is mantissa
        // target = mantissa * 2^(8*(exponent-3))
        //
        // For XMRig, we need to provide a target that when the hash is below it,
        // represents valid work. Since we're using XMRig as a nonce generator,
        // we'll use an easier target so it submits frequently, then validate ourselves.
        //
        // Set a moderate share difficulty - let XMRig submit every few seconds
        // Easy target = high value like "ffffffff" means almost any hash is accepted
        // Medium target = something like "00000fff00000000"
        //
        // Use a very easy share target so XMRig submits frequently
        // We do the real validation server-side with the actual WATTx target
        // "b88d0600" = difficulty ~1000, shares every few seconds
        // "00ffffff" = difficulty ~16M, shares every ~10 seconds at 2kH/s
        // "ffffffff" = difficulty 1, instant shares
        job.target = "b88d0600";  // ~1000 difficulty - XMRig submits frequently

        LogPrintf("Stratum: Real target (nBits=0x%08x) = %s, share target = %s\n",
                  block.nBits, target.GetHex(), job.target);

        LogPrintf("Stratum: Created job blob=%d bytes, target=%s, fullHeader=%d bytes\n",
                  miningBlob.size(), job.target, fullHeader.size());

        // Seed hash - for RandomX, use genesis block hash as key
        // Note: The actual seed should be based on epoch, but for simplicity use prev block
        job.seed_hash = block.hashPrevBlock.GetHex();

        // Store job
        {
            std::lock_guard<std::mutex> lock(m_jobs_mutex);
            m_jobs[job.job_id] = job;
            m_current_job = job;

            // Limit stored jobs
            if (m_jobs.size() > 10) {
                auto oldest = m_jobs.begin();
                m_jobs.erase(oldest);
            }
        }

        // Broadcast to all clients
        BroadcastJob(job);

        LogPrintf("Stratum: New job %s at height %d\n", job.job_id, job.height);

    } catch (const std::exception& e) {
        LogPrintf("Stratum: Error creating job: %s\n", e.what());
    }
}

void StratumServer::BroadcastJob(const StratumJob& job) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    for (auto& [id, client] : m_clients) {
        if (client->subscribed && client->authorized) {
            SendJob(id, job);
        }
    }
}

void StratumServer::SendJob(int client_id, const StratumJob& job) {
    // XMRig-compatible job notification
    std::ostringstream msg;
    msg << "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{";
    msg << "\"blob\":\"" << job.blob << "\",";
    msg << "\"job_id\":\"" << job.job_id << "\",";
    msg << "\"target\":\"" << job.target << "\",";
    msg << "\"algo\":\"rx/0\",";  // RandomX algorithm
    msg << "\"height\":" << job.height << ",";
    msg << "\"seed_hash\":\"" << job.seed_hash << "\"";
    msg << "}}\n";

    SendToClient(client_id, msg.str());
}

bool StratumServer::ValidateAndSubmitShare(int client_id, const std::string& job_id,
                                            const std::string& nonce_hex, const std::string& result_hex) {
    StratumJob job;
    {
        std::lock_guard<std::mutex> lock(m_jobs_mutex);
        auto it = m_jobs.find(job_id);
        if (it == m_jobs.end()) {
            LogPrintf("Stratum: Unknown job_id %s\n", job_id);
            return false;
        }
        job = it->second;
    }

    if (!job.block_template) {
        LogPrintf("Stratum: No block template for job %s\n", job_id);
        return false;
    }

    try {
        // Parse nonce (XMRig sends 4 bytes in little-endian hex)
        uint32_t nonce = 0;
        if (nonce_hex.length() == 8) {
            // 4 bytes hex = 8 chars, little endian
            auto nonce_bytes = ParseHex(nonce_hex);
            if (nonce_bytes.size() == 4) {
                nonce = nonce_bytes[0] | (nonce_bytes[1] << 8) |
                        (nonce_bytes[2] << 16) | (nonce_bytes[3] << 24);
            }
        }

        LogPrintf("Stratum: Validating share - job_id=%s nonce=0x%08x result=%s\n",
                  job_id, nonce, result_hex.substr(0, 16));

        // Get block from template for validation
        CBlock block = job.block_template->getBlock();
        block.nNonce = nonce;

        // Ensure RandomX is initialized with the genesis block hash
        const CChainParams& chainParams = Params();
        uint256 genesisHash = chainParams.GenesisBlock().GetHash();

        auto& miner = node::GetRandomXMiner();
        if (!miner.IsInitialized()) {
            LogPrintf("Stratum: Initializing RandomX for validation...\n");
            if (!miner.Initialize(genesisHash.data(), 32, node::RandomXMiner::Mode::LIGHT)) {
                LogPrintf("Stratum: Failed to initialize RandomX\n");
                return false;
            }
        }

        // Compute RandomX hash of the full serialized header
        auto headerData = node::RandomXMiner::SerializeBlockHeader(block);

        uint256 hash;
        miner.CalculateHash(headerData.data(), headerData.size(), hash.data());

        // Check against target
        arith_uint256 target;
        target.SetCompact(block.nBits);

        arith_uint256 hashArith = UintToArith256(hash);

        LogPrintf("Stratum: Hash=%s target=%s\n",
                  hash.GetHex().substr(0, 16) + "...",
                  target.GetHex().substr(0, 16) + "...");

        if (hashArith > target) {
            // Share above target - this is expected most of the time since
            // XMRig is solving a different puzzle
            LogPrintf("Stratum: Share above target (hash > target)\n");
            return false;
        }

        // Valid block! Submit it via the BlockTemplate interface
        LogPrintf("Stratum: BLOCK FOUND! hash=%s nonce=%u\n", hash.GetHex(), nonce);

        // Submit using submitSolution - pass version, timestamp, nonce, and coinbase
        CTransactionRef coinbase = job.block_template->getCoinbaseTx();
        bool accepted = job.block_template->submitSolution(block.nVersion, block.nTime, nonce, coinbase);

        if (accepted) {
            m_blocks_found++;
            LogPrintf("Stratum: Block accepted!\n");

            // Create new job for next block
            NotifyNewBlock();
            return true;
        } else {
            LogPrintf("Stratum: Block rejected by node\n");
            return false;
        }

    } catch (const std::exception& e) {
        LogPrintf("Stratum: Error validating share: %s\n", e.what());
        return false;
    }
}

void StratumServer::NotifyNewBlock() {
    m_job_cv.notify_all();
}

void StratumServer::SendToClient(int client_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    auto it = m_clients.find(client_id);
    if (it == m_clients.end()) return;

    send(it->second->socket_fd, message.c_str(), message.length(), 0);
}

void StratumServer::SendResult(int client_id, const std::string& id, const std::string& result) {
    std::ostringstream response;
    response << "{\"id\":" << id << ",\"result\":" << result << ",\"error\":null}\n";
    SendToClient(client_id, response.str());
}

void StratumServer::SendError(int client_id, const std::string& id, int code, const std::string& message) {
    std::ostringstream response;
    response << "{\"id\":" << id << ",\"result\":null,\"error\":[" << code << ",\"" << message << "\",null]}\n";
    SendToClient(client_id, response.str());
}

void StratumServer::DisconnectClient(int client_id) {
    std::lock_guard<std::mutex> lock(m_clients_mutex);
    auto it = m_clients.find(client_id);
    if (it != m_clients.end()) {
        if (it->second->socket_fd >= 0) {
#ifdef WIN32
            closesocket(it->second->socket_fd);
#else
            close(it->second->socket_fd);
#endif
        }
        m_clients.erase(it);
        LogPrintf("Stratum: Client %d removed\n", client_id);
    }
}

std::string StratumServer::GenerateJobId() {
    uint64_t id = m_job_counter.fetch_add(1);
    std::ostringstream ss;
    ss << std::hex << GetTime() << std::setfill('0') << std::setw(8) << id;
    return ss.str();
}

std::string StratumServer::GenerateSessionId() {
    std::vector<unsigned char> rand_bytes(16);
    GetRandBytes(rand_bytes);
    return HexStr(rand_bytes);
}

} // namespace stratum
