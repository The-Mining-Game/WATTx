// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_SERVER_H
#define WATTX_STRATUM_SERVER_H

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <uint256.h>

class CBlock;
class CBlockIndex;
namespace interfaces {
class Mining;
class BlockTemplate;
}

namespace stratum {

// Stratum job data sent to miners
struct StratumJob {
    std::string job_id;
    std::string blob;           // Block header blob (hex)
    std::string target;         // Mining target (hex)
    uint64_t height;
    std::string seed_hash;      // RandomX seed hash
    std::string prev_hash;      // Previous block hash
    int64_t timestamp;
    uint32_t bits;

    // Full block template for submission
    std::shared_ptr<interfaces::BlockTemplate> block_template;
};

// Connected miner client
struct StratumClient {
    int socket_fd;
    std::string worker_name;
    std::string wallet_address;
    bool authorized;
    bool subscribed;
    std::string session_id;
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    int64_t connect_time;
    int64_t last_activity;
    std::string recv_buffer;

    StratumClient() : socket_fd(-1), authorized(false), subscribed(false),
                      shares_accepted(0), shares_rejected(0), connect_time(0), last_activity(0) {}
};

// Stratum server configuration
struct StratumConfig {
    std::string bind_address = "0.0.0.0";
    uint16_t port = 3335;
    int max_clients = 100;
    int job_timeout_seconds = 60;
    std::string default_wallet;  // Default wallet for coinbase if miner doesn't specify
};

class StratumServer {
public:
    StratumServer();
    ~StratumServer();

    // Server lifecycle
    bool Start(const StratumConfig& config, interfaces::Mining* mining);
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Get server info
    uint16_t GetPort() const { return m_config.port; }
    size_t GetClientCount() const;
    uint64_t GetTotalSharesAccepted() const { return m_total_shares_accepted.load(); }
    uint64_t GetTotalSharesRejected() const { return m_total_shares_rejected.load(); }
    uint64_t GetBlocksFound() const { return m_blocks_found.load(); }

    // Notify all clients of new job (called when new block arrives)
    void NotifyNewBlock();

private:
    // Server threads
    void AcceptThread();
    void ClientThread(int client_id);
    void JobThread();

    // Protocol handlers
    void HandleMessage(int client_id, const std::string& message);
    void HandleSubscribe(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleAuthorize(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleSubmit(int client_id, const std::string& id, const std::vector<std::string>& params);
    void HandleGetJob(int client_id, const std::string& id, const std::vector<std::string>& params);

    // Job management
    void CreateNewJob();
    void BroadcastJob(const StratumJob& job);
    bool ValidateAndSubmitShare(int client_id, const std::string& job_id,
                                 const std::string& nonce, const std::string& result);

    // Network helpers
    void SendToClient(int client_id, const std::string& message);
    void SendResult(int client_id, const std::string& id, const std::string& result);
    void SendError(int client_id, const std::string& id, int code, const std::string& message);
    void SendJob(int client_id, const StratumJob& job);
    void DisconnectClient(int client_id);

    // Generate unique IDs
    std::string GenerateJobId();
    std::string GenerateSessionId();

    // Configuration
    StratumConfig m_config;
    interfaces::Mining* m_mining{nullptr};

    // Server state
    std::atomic<bool> m_running{false};
    int m_listen_socket{-1};

    // Threads
    std::thread m_accept_thread;
    std::thread m_job_thread;
    std::vector<std::thread> m_client_threads;

    // Clients
    mutable std::mutex m_clients_mutex;
    std::unordered_map<int, std::unique_ptr<StratumClient>> m_clients;
    int m_next_client_id{0};

    // Jobs
    mutable std::mutex m_jobs_mutex;
    std::unordered_map<std::string, StratumJob> m_jobs;
    StratumJob m_current_job;
    std::atomic<uint64_t> m_job_counter{0};

    // Statistics
    std::atomic<uint64_t> m_total_shares_accepted{0};
    std::atomic<uint64_t> m_total_shares_rejected{0};
    std::atomic<uint64_t> m_blocks_found{0};

    // Synchronization
    std::condition_variable m_job_cv;
    std::mutex m_job_cv_mutex;
};

// Global stratum server instance
StratumServer& GetStratumServer();

} // namespace stratum

#endif // WATTX_STRATUM_SERVER_H
