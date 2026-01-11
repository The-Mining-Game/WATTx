// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/randomx_miner.h>
#include <logging.h>
#include <util/time.h>
#include <streams.h>
#include <hash.h>
#include <arith_uint256.h>

#include <randomx.h>

#include <chrono>
#include <cstring>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>
#endif

namespace node {

// Global miner instance
static std::unique_ptr<RandomXMiner> g_randomx_miner;

RandomXMiner& GetRandomXMiner() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        g_randomx_miner = std::make_unique<RandomXMiner>();
    });
    return *g_randomx_miner;
}

RandomXMiner::RandomXMiner() {
    m_flags = GetRecommendedFlags();
    LogPrintf("RandomX: Initialized with flags 0x%x (AES=%d, JIT=%d)\n",
              m_flags,
              (m_flags & RANDOMX_FLAG_HARD_AES) ? 1 : 0,
              (m_flags & RANDOMX_FLAG_JIT) ? 1 : 0);
}

RandomXMiner::~RandomXMiner() {
    StopMining();
    Cleanup();
}

// Internal cleanup without locking - called when mutex is already held
void RandomXMiner::CleanupInternal() {
    // Destroy mining VMs first
    for (auto* vm : m_vms) {
        if (vm) {
            randomx_destroy_vm(vm);
        }
    }
    m_vms.clear();

    // Destroy validation VM (separate from mining VMs)
    if (m_validationVm) {
        randomx_destroy_vm(m_validationVm);
        m_validationVm = nullptr;
    }

    // Release dataset
    if (m_dataset) {
        randomx_release_dataset(m_dataset);
        m_dataset = nullptr;
    }

    // Release cache
    if (m_cache) {
        randomx_release_cache(m_cache);
        m_cache = nullptr;
    }

    m_initialized = false;
}

void RandomXMiner::Cleanup() {
    std::lock_guard<std::mutex> lock(m_mutex);
    CleanupInternal();
}

unsigned RandomXMiner::GetRecommendedFlags() {
    return randomx_get_flags();
}

bool RandomXMiner::HasHardwareAES() {
    unsigned flags = randomx_get_flags();
    return (flags & RANDOMX_FLAG_HARD_AES) != 0;
}

bool RandomXMiner::HasLargePages() {
    // Try to allocate a small test with large pages
    // This is a heuristic - actual large page availability depends on system config
#ifdef __linux__
    // On Linux, check if huge pages are available
    FILE* fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "HugePages_Total:", 16) == 0) {
                int total = 0;
                sscanf(line + 16, "%d", &total);
                fclose(fp);
                return total > 0;
            }
        }
        fclose(fp);
    }
#endif
    return false;
}

bool RandomXMiner::Initialize(const void* key, size_t keySize, Mode mode, bool safeMode) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Cleanup any existing context (use internal version since we already hold the lock)
    if (m_initialized) {
        CleanupInternal();
    }

    m_mode = mode;
    m_safeMode = safeMode;

    // Determine flags
    unsigned flags = m_flags;
    if (mode == Mode::FULL) {
        flags |= RANDOMX_FLAG_FULL_MEM;
    }

    // Safe mode: disable JIT and AVX2 to prevent invalid opcode crashes
    if (safeMode) {
        LogPrintf("RandomX: Safe mode enabled - disabling JIT and AVX2\n");
        flags &= ~RANDOMX_FLAG_JIT;
        flags &= ~RANDOMX_FLAG_ARGON2_AVX2;
        // Keep SSSE3 and HARD_AES as they are more stable
    }

    // Allocate cache
    LogPrintf("RandomX: Allocating cache (flags=0x%x)...\n", flags);
    m_cache = randomx_alloc_cache(static_cast<randomx_flags>(flags));
    if (!m_cache) {
        LogPrintf("RandomX: Failed to allocate cache, trying without JIT...\n");
        // Try again without JIT
        flags &= ~RANDOMX_FLAG_JIT;
        m_cache = randomx_alloc_cache(static_cast<randomx_flags>(flags));
        if (!m_cache) {
            LogPrintf("RandomX: Failed to allocate cache\n");
            return false;
        }
    }

    // Initialize cache with key
    LogPrintf("RandomX: Initializing cache with key (%zu bytes)...\n", keySize);
    randomx_init_cache(m_cache, key, keySize);

    // Save current key
    m_currentKey.assign(static_cast<const unsigned char*>(key),
                        static_cast<const unsigned char*>(key) + keySize);

    // For full mode, allocate and initialize dataset
    if (mode == Mode::FULL) {
        LogPrintf("RandomX: Allocating dataset (~2GB, this may take a while)...\n");
        m_dataset = randomx_alloc_dataset(static_cast<randomx_flags>(flags));
        if (!m_dataset) {
            LogPrintf("RandomX: Failed to allocate dataset, falling back to light mode\n");
            m_mode = Mode::LIGHT;
        } else {
            // Initialize dataset (this is slow - can take 30+ seconds)
            unsigned long itemCount = randomx_dataset_item_count();
            LogPrintf("RandomX: Initializing dataset (%lu items)...\n", itemCount);

            // Use multiple threads for dataset initialization
            unsigned numThreads = std::thread::hardware_concurrency();
            if (numThreads < 1) numThreads = 1;

            std::vector<std::thread> initThreads;
            unsigned long itemsPerThread = itemCount / numThreads;

            for (unsigned i = 0; i < numThreads; i++) {
                unsigned long startItem = i * itemsPerThread;
                unsigned long count = (i == numThreads - 1) ?
                    (itemCount - startItem) : itemsPerThread;

                initThreads.emplace_back([this, startItem, count]() {
                    randomx_init_dataset(m_dataset, m_cache, startItem, count);
                });
            }

            for (auto& t : initThreads) {
                t.join();
            }

            LogPrintf("RandomX: Dataset initialization complete\n");
        }
    }

    m_flags = flags;
    m_initialized = true;
    LogPrintf("RandomX: Initialization complete (mode=%s)\n",
              m_mode == Mode::FULL ? "FULL" : "LIGHT");
    return true;
}

bool RandomXMiner::ReinitializeIfNeeded(const void* key, size_t keySize) {
    // Check if key has changed
    if (m_currentKey.size() == keySize &&
        std::memcmp(m_currentKey.data(), key, keySize) == 0) {
        return true;  // Key unchanged, no reinitialization needed
    }

    LogPrintf("RandomX: Key changed, reinitializing...\n");
    return Initialize(key, keySize, m_mode);
}

void RandomXMiner::CalculateHash(const void* input, size_t inputSize, void* output) {
    std::lock_guard<std::mutex> lock(m_vmMutex);

    if (!m_initialized) {
        LogPrintf("RandomX: Not initialized, cannot calculate hash\n");
        std::memset(output, 0, HASH_SIZE);
        return;
    }

    // Use dedicated validation VM (separate from mining VMs to avoid race conditions)
    // This VM is created on first use and protected by m_vmMutex
    if (!m_validationVm) {
        m_validationVm = randomx_create_vm(
            static_cast<randomx_flags>(m_flags),
            m_cache,
            m_dataset
        );
        if (!m_validationVm) {
            LogPrintf("RandomX: Failed to create validation VM\n");
            std::memset(output, 0, HASH_SIZE);
            return;
        }
    }

    randomx_calculate_hash(m_validationVm, input, inputSize, output);
}

bool RandomXMiner::MeetsTarget(const uint256& hash, const uint256& target) {
    // Hash must be <= target (lower hash = more difficult)
    // Use arith_uint256 for proper big-endian PoW comparison
    return UintToArith256(hash) <= UintToArith256(target);
}

std::vector<unsigned char> RandomXMiner::SerializeBlockHeader(const CBlockHeader& header) {
    DataStream ss{};
    // Serialize ALL block header fields (must match CBlockHeader::SERIALIZE_METHODS)
    ss << header.nVersion;
    ss << header.hashPrevBlock;
    ss << header.hashMerkleRoot;
    ss << header.nTime;
    ss << header.nBits;
    ss << header.nNonce;
    // QTUM/WATTx state roots (required for EVM compatibility)
    ss << header.hashStateRoot;
    ss << header.hashUTXORoot;
    // Proof-of-stake fields
    ss << header.prevoutStake;
    ss << header.vchBlockSigDlgt;
    // Gapcoin legacy PoW fields (kept for block format compatibility)
    ss << header.nShift;
    ss << header.nAdder;
    ss << header.nGapSize;
    // Convert std::byte to unsigned char
    std::vector<unsigned char> result(ss.size());
    std::memcpy(result.data(), ss.data(), ss.size());
    return result;
}

void RandomXMiner::SetLowThreadPriority() {
#ifndef WIN32
    // Set nice value to lowest priority
    (void)nice(19);

    // Set scheduling policy to batch (CPU-intensive, low priority)
    struct sched_param param;
    param.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
#else
    // On Windows, set thread priority to lowest
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
#endif
}

void RandomXMiner::StartMining(const CBlock& block, const uint256& target,
                                int numThreads, BlockFoundCallback callback) {
    // Stop any existing mining
    StopMining();

    if (!m_initialized) {
        LogPrintf("RandomX: Cannot start mining - not initialized\n");
        return;
    }

    if (numThreads <= 0) {
        numThreads = std::max(1, static_cast<int>(std::thread::hardware_concurrency()) - 1);
    }

    LogPrintf("RandomX: Starting mining with %d threads\n", numThreads);

    m_stopMining = false;
    m_mining = true;
    m_totalHashes = 0;
    m_miningStartTime = GetTime();

    // Initialize session tracking on first block (don't reset between blocks)
    if (m_sessionStartTime == 0) {
        m_sessionStartTime = GetTime();
        m_sessionHashes = 0;
        m_recentWindowStart = GetTime();
        m_recentHashes = 0;
    }

    // Create VMs for each thread
    {
        std::lock_guard<std::mutex> lock(m_vmMutex);
        while (m_vms.size() < static_cast<size_t>(numThreads)) {
            randomx_vm* vm = randomx_create_vm(
                static_cast<randomx_flags>(m_flags),
                m_cache,
                m_dataset
            );
            if (!vm) {
                LogPrintf("RandomX: Failed to create VM for thread %zu\n", m_vms.size());
                break;
            }
            m_vms.push_back(vm);
        }
        numThreads = std::min(numThreads, static_cast<int>(m_vms.size()));
    }

    if (numThreads == 0) {
        LogPrintf("RandomX: No VMs available, cannot mine\n");
        m_mining = false;
        return;
    }

    // Split nonce range among threads
    uint32_t nonceRange = UINT32_MAX / numThreads;

    for (int i = 0; i < numThreads; i++) {
        uint32_t startNonce = i * nonceRange;
        m_threads.emplace_back(&RandomXMiner::MineThread, this,
                               i, block, target, startNonce, nonceRange, callback);
    }
}

void RandomXMiner::MineThread(int threadId, CBlock block, uint256 target,
                               uint32_t startNonce, uint32_t nonceRange,
                               BlockFoundCallback callback) {
    SetLowThreadPriority();

    LogPrintf("RandomX: Mining thread %d started (nonce %u - %u)\n",
              threadId, startNonce, startNonce + nonceRange - 1);

    // Get VM for this thread
    randomx_vm* vm = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_vmMutex);
        if (static_cast<size_t>(threadId) < m_vms.size()) {
            vm = m_vms[threadId];
        }
    }

    if (!vm) {
        LogPrintf("RandomX: Thread %d has no VM\n", threadId);
        return;
    }

    uint32_t nonce = startNonce;
    uint64_t hashCount = 0;
    unsigned char hashOutput[HASH_SIZE];

    while (!m_stopMining && nonce < startNonce + nonceRange) {
        block.nNonce = nonce;

        // Serialize block header
        auto headerData = SerializeBlockHeader(block);

        // Calculate RandomX hash
        randomx_calculate_hash(vm, headerData.data(), headerData.size(), hashOutput);

        // Convert to uint256
        uint256 hash;
        std::memcpy(hash.data(), hashOutput, HASH_SIZE);

        hashCount++;

        // Update session counter periodically (every 100 hashes) for live hashrate display
        if ((hashCount & 0x3F) == 0) {  // Every 64 hashes
            m_sessionHashes += 64;
            m_totalHashes += 64;
        }

        // Debug logging every 10000 hashes to see hash values
        if (hashCount == 1 && threadId == 0) {
            LogPrintf("RandomX: First hash=%s target=%s\n",
                      hash.ToString(), target.ToString());
        }

        // Check if meets target
        if (MeetsTarget(hash, target)) {
            LogPrintf("RandomX: Thread %d found valid block! nonce=%u hash=%s\n",
                      threadId, nonce, hash.ToString());

            m_stopMining = true;

            if (callback) {
                callback(block);
            }
            break;
        }

        // Yield periodically to prevent UI freeze
        if ((nonce & 0xFF) == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        nonce++;
    }

    // Add remaining hashes not yet counted (hashCount % 64)
    uint64_t remainingHashes = hashCount & 0x3F;  // hashCount % 64
    m_totalHashes += remainingHashes;
    m_sessionHashes += remainingHashes;
    m_recentHashes += remainingHashes;
    LogPrintf("RandomX: Thread %d stopped after %lu hashes (session: %lu)\n",
              threadId, hashCount, m_sessionHashes.load());
}

void RandomXMiner::StopMining() {
    if (!m_mining) return;

    LogPrintf("RandomX: Stopping mining...\n");
    m_stopMining = true;

    // Save current hashrate before stopping
    if (m_sessionStartTime > 0) {
        int64_t elapsed = GetTime() - m_sessionStartTime;
        if (elapsed > 0) {
            m_lastHashrate = static_cast<double>(m_sessionHashes.load()) / elapsed;
        }
    }

    for (auto& t : m_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    m_threads.clear();

    m_mining = false;

    // Reset session when fully stopped (next start begins fresh session)
    m_sessionStartTime = 0;
    m_sessionHashes = 0;
    m_recentWindowStart = 0;
    m_recentHashes = 0;

    LogPrintf("RandomX: Mining stopped\n");
}

double RandomXMiner::GetHashrate() const {
    // If not mining, return last known hashrate
    if (!m_mining) {
        return m_lastHashrate.load();
    }

    // Use session-based hashrate (persists across block changes)
    if (m_sessionStartTime == 0) {
        return m_lastHashrate.load();
    }

    int64_t elapsed = GetTime() - m_sessionStartTime;
    if (elapsed <= 0) {
        return m_lastHashrate.load();
    }

    // Calculate session hashrate
    double sessionHashrate = static_cast<double>(m_sessionHashes.load()) / elapsed;

    // Also calculate recent window hashrate (last 10 seconds) for smoother display
    int64_t recentElapsed = GetTime() - m_recentWindowStart;
    if (recentElapsed >= 10) {
        // Reset window every 10 seconds for rolling average
        m_recentWindowStart = GetTime();
        m_recentHashes = 0;
    }

    // Return session hashrate (more stable)
    m_lastHashrate = sessionHashrate;
    return sessionHashrate;
}

} // namespace node
