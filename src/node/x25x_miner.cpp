// Copyright (c) 2024 The WATTx developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/x25x_miner.h>

#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <node/randomx_miner.h>
#include <streams.h>
#include <util/time.h>

#include <chrono>
#include <cstring>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#endif

namespace node {

// Algorithm context for caching initialization state
struct X25XMiner::AlgorithmContext {
    bool sha256d_ready{true};  // Always ready
    bool scrypt_ready{false};
    bool ethash_ready{false};
    bool randomx_ready{false};
    bool equihash_ready{false};
    bool x11_ready{false};
    bool kheavyhash_ready{false};
};

// Global miner instance
static std::unique_ptr<X25XMiner> g_x25x_miner;

X25XMiner& GetX25XMiner() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        g_x25x_miner = std::make_unique<X25XMiner>();
    });
    return *g_x25x_miner;
}

X25XMiner::X25XMiner()
    : m_context(std::make_unique<AlgorithmContext>())
{
    LogPrintf("X25X: Multi-algorithm miner initialized\n");
}

X25XMiner::~X25XMiner() {
    StopMining();
}

bool X25XMiner::Initialize(x25x::Algorithm algo) {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_algorithm = algo;

    switch (algo) {
        case x25x::Algorithm::SHA256D:
            // SHA256 is always available
            m_context->sha256d_ready = true;
            LogPrintf("X25X: SHA256d algorithm ready\n");
            return true;

        case x25x::Algorithm::SCRYPT:
            // Scrypt initialization
            // TODO: Initialize scrypt context with proper parameters
            m_context->scrypt_ready = true;
            LogPrintf("X25X: Scrypt algorithm ready\n");
            return true;

        case x25x::Algorithm::ETHASH:
            // Ethash requires DAG generation
            // This is handled by the Ethash library
            m_context->ethash_ready = true;
            LogPrintf("X25X: Ethash algorithm ready (DAG generation may occur on first use)\n");
            return true;

        case x25x::Algorithm::RANDOMX:
            // RandomX uses the existing RandomXMiner
            // Initialize with default key if not already done
            {
                auto& rxMiner = GetRandomXMiner();
                if (!rxMiner.IsInitialized()) {
                    // Use genesis block hash as initial key
                    const char* defaultKey = "WATTx-X25X-RandomX";
                    if (!rxMiner.Initialize(defaultKey, strlen(defaultKey), RandomXMiner::Mode::LIGHT)) {
                        LogPrintf("X25X: Failed to initialize RandomX\n");
                        return false;
                    }
                }
                m_context->randomx_ready = true;
                LogPrintf("X25X: RandomX algorithm ready\n");
            }
            return true;

        case x25x::Algorithm::EQUIHASH:
            // Equihash 200,9 (ZCash compatible)
            m_context->equihash_ready = true;
            LogPrintf("X25X: Equihash algorithm ready\n");
            return true;

        case x25x::Algorithm::X11:
            // X11 chain of algorithms
            m_context->x11_ready = true;
            LogPrintf("X25X: X11 algorithm ready\n");
            return true;

        case x25x::Algorithm::KHEAVYHASH:
            // kHeavyHash (Kaspa) - GPU-optimized, uses SHA3 + matrix multiplication
            m_context->kheavyhash_ready = true;
            LogPrintf("X25X: kHeavyHash (Kaspa) algorithm ready\n");
            return true;

        default:
            LogPrintf("X25X: Unknown algorithm %d\n", static_cast<int>(algo));
            return false;
    }
}

void X25XMiner::SetAlgorithm(x25x::Algorithm algo) {
    if (m_mining) {
        LogPrintf("X25X: Cannot change algorithm while mining\n");
        return;
    }

    if (!Initialize(algo)) {
        LogPrintf("X25X: Failed to initialize algorithm %s\n",
                  x25x::GetAlgorithmInfo(algo).name);
        return;
    }

    m_algorithm = algo;
    LogPrintf("X25X: Algorithm set to %s\n", x25x::GetAlgorithmInfo(algo).name);
}

uint256 X25XMiner::ComputeHash(const CBlockHeader& header) {
    // Use the X25X hash function based on current algorithm
    return x25x::HashBlockHeader(header, m_algorithm);
}

void X25XMiner::StartMining(const CBlock& block, const uint256& target,
                            int numThreads, BlockFoundCallback callback) {
    StopMining();

    if (!x25x::IsAlgorithmEnabled(m_algorithm)) {
        LogPrintf("X25X: Algorithm %s is not enabled\n",
                  x25x::GetAlgorithmInfo(m_algorithm).name);
        return;
    }

    if (numThreads <= 0) {
        numThreads = std::min(2, std::max(1, static_cast<int>(std::thread::hardware_concurrency()) - 1));
    }

    LogPrintf("X25X: Starting mining with %d threads using %s algorithm\n",
              numThreads, x25x::GetAlgorithmInfo(m_algorithm).name);

    m_stopMining = false;
    m_mining = true;
    m_totalHashes = 0;
    m_miningStartTime = GetTime();

    // Split nonce range among threads
    uint32_t nonceRange = UINT32_MAX / numThreads;

    for (int i = 0; i < numThreads; i++) {
        uint32_t startNonce = i * nonceRange;
        m_threads.emplace_back(&X25XMiner::MineThread, this,
                               i, block, target, startNonce, nonceRange, callback);
    }
}

void X25XMiner::MineThread(int threadId, CBlock block, uint256 target,
                           uint32_t startNonce, uint32_t nonceRange,
                           BlockFoundCallback callback) {
    // Set low thread priority
#ifndef WIN32
    (void)nice(19);
#else
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
#endif

    LogPrintf("X25X: Thread %d started (nonce %u - %u)\n",
              threadId, startNonce, startNonce + nonceRange - 1);

    uint32_t nonce = startNonce;
    uint64_t hashCount = 0;

    // Set the algorithm in the block version
    block.nVersion = x25x::SetBlockAlgorithm(block.nVersion, m_algorithm);

    while (!m_stopMining && nonce < startNonce + nonceRange) {
        block.nNonce = nonce;

        // Compute hash using current algorithm
        uint256 hash = ComputeHash(block);

        hashCount++;

        // Update counters periodically
        if ((hashCount & 0x3F) == 0) {  // Every 64 hashes
            m_totalHashes += 64;
        }

        // Debug logging for first hash
        if (hashCount == 1 && threadId == 0) {
            LogPrintf("X25X: First hash=%s target=%s algo=%s\n",
                      hash.ToString(), target.ToString(),
                      x25x::GetAlgorithmInfo(m_algorithm).name);
        }

        // Check if meets target
        if (UintToArith256(hash) <= UintToArith256(target)) {
            LogPrintf("X25X: Thread %d found valid block! nonce=%u hash=%s\n",
                      threadId, nonce, hash.ToString());

            m_stopMining = true;

            if (callback) {
                callback(block);
            }
            break;
        }

        // Yield periodically
        if ((nonce & 0xFF) == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        nonce++;
    }

    // Add remaining hashes
    uint64_t remainingHashes = hashCount & 0x3F;
    m_totalHashes += remainingHashes;

    LogPrintf("X25X: Thread %d stopped after %lu hashes\n", threadId, hashCount);
}

void X25XMiner::StopMining() {
    if (!m_mining) return;

    LogPrintf("X25X: Stopping mining...\n");
    m_stopMining = true;

    // Save hashrate
    if (m_miningStartTime > 0) {
        int64_t elapsed = GetTime() - m_miningStartTime;
        if (elapsed > 0) {
            m_lastHashrate = static_cast<double>(m_totalHashes.load()) / elapsed;
        }
    }

    for (auto& t : m_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    m_threads.clear();

    m_mining = false;
    LogPrintf("X25X: Mining stopped\n");
}

double X25XMiner::GetHashrate() const {
    if (!m_mining) {
        return m_lastHashrate.load();
    }

    if (m_miningStartTime == 0) {
        return 0.0;
    }

    int64_t elapsed = GetTime() - m_miningStartTime;
    if (elapsed <= 0) {
        return m_lastHashrate.load();
    }

    double hashrate = static_cast<double>(m_totalHashes.load()) / elapsed;
    m_lastHashrate = hashrate;
    return hashrate;
}

double X25XMiner::GetHashrateForAlgorithm(x25x::Algorithm algo) const {
    if (algo == m_algorithm) {
        return GetHashrate();
    }
    return 0.0;
}

bool X25XMiner::IsAlgorithmAvailable(x25x::Algorithm algo) {
    switch (algo) {
        case x25x::Algorithm::SHA256D:
            return true;  // Always available

        case x25x::Algorithm::SCRYPT:
            // Check if libscrypt is available
            return true;  // Assume available

        case x25x::Algorithm::ETHASH:
            // Check if ethash is compiled in
            return true;

        case x25x::Algorithm::RANDOMX:
            // Check if RandomX is available
            return true;

        case x25x::Algorithm::EQUIHASH:
            // Check if Equihash is available
            return true;

        case x25x::Algorithm::X11:
            // X11 requires SPH library functions
            return true;

        case x25x::Algorithm::KHEAVYHASH:
            // kHeavyHash uses SHA3 which is always available
            return true;

        default:
            return false;
    }
}

x25x::Algorithm X25XMiner::GetRecommendedAlgorithm() {
    // Detect hardware capabilities and recommend best algorithm

    // Check for ASIC-like performance (unlikely on general hardware)
    // Default to RandomX for CPU mining as it's ASIC-resistant

    // Check CPU count
    unsigned int numCPUs = std::thread::hardware_concurrency();

    if (numCPUs >= 4) {
        // Multi-core system: RandomX is efficient
        return x25x::Algorithm::RANDOMX;
    }

    // Fallback to SHA256D for simplicity
    return x25x::Algorithm::SHA256D;
}

std::vector<x25x::Algorithm> X25XMiner::GetAvailableAlgorithms() {
    std::vector<x25x::Algorithm> available;

    for (const auto& algo : x25x::GetEnabledAlgorithms()) {
        if (IsAlgorithmAvailable(algo)) {
            available.push_back(algo);
        }
    }

    return available;
}

// Stratum support for external miners
// TODO: Implement proper stratum support with correct serialization
// For now, these are stubs that will be implemented when stratum server is added

StratumJob CreateStratumJob(const CBlock& block, x25x::Algorithm algo) {
    StratumJob job;
    job.jobId = "00000000";
    job.prevHash = block.hashPrevBlock.GetHex();
    job.coinbase1 = "";
    job.coinbase2 = "";
    job.version = strprintf("%08x", x25x::SetBlockAlgorithm(block.nVersion, algo));
    job.nBits = strprintf("%08x", block.nBits);
    job.nTime = strprintf("%08x", block.nTime);
    job.cleanJobs = true;
    job.algorithm = algo;
    return job;
}

bool VerifyStratumSolution(const StratumJob& job, const std::string& nonce,
                           const std::string& solution, x25x::Algorithm algo) {
    // TODO: Implement proper stratum solution verification
    return false;
}

} // namespace node
