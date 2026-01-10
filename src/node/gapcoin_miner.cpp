// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/gapcoin_miner.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <util/time.h>
#include <opencl/opencl_runtime.h>
#include <opencl/gpu_sieve.h>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <thread>

#ifndef WIN32
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>
#endif

namespace node {

// Set current thread to low priority to avoid starving UI
static void SetLowThreadPriority() {
#ifndef WIN32
    // Use nice() to lower priority - this works without root
    // Nice value 19 is the lowest priority
    nice(19);

    // Also try SCHED_BATCH which doesn't require root
    struct sched_param param;
    param.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
#endif
}

std::vector<uint32_t> GenerateSmallPrimes(uint32_t limit) {
    std::vector<uint32_t> primes;
    std::vector<bool> sieve(limit + 1, true);
    sieve[0] = sieve[1] = false;

    for (uint32_t i = 2; i <= limit; ++i) {
        if (sieve[i]) {
            primes.push_back(i);
            for (uint64_t j = (uint64_t)i * i; j <= limit; j += i) {
                sieve[j] = false;
            }
        }
    }
    return primes;
}

std::vector<uint8_t> GenerateWheelPattern(uint32_t modulus) {
    std::vector<uint8_t> pattern;
    for (uint32_t i = 1; i < modulus; ++i) {
        bool coprime = true;
        if (modulus % 2 == 0 && i % 2 == 0) coprime = false;
        if (modulus % 3 == 0 && i % 3 == 0) coprime = false;
        if (modulus % 5 == 0 && i % 5 == 0) coprime = false;
        if (modulus % 7 == 0 && i % 7 == 0) coprime = false;
        if (coprime) pattern.push_back(i);
    }
    return pattern;
}

GapcoinMiner::GapcoinMiner(unsigned int nThreads, size_t nSieveSize, size_t nSievePrimes)
    : m_nThreads(nThreads == 0 ? std::thread::hardware_concurrency() : nThreads)
    , m_nSieveSize(nSieveSize)
    , m_nSievePrimes(nSievePrimes)
{
    if (m_nThreads == 0) m_nThreads = 1;
    InitializeSieve();
}

GapcoinMiner::~GapcoinMiner() {
    StopMining();
}

void GapcoinMiner::InitializeSieve() {
    uint32_t primeLimit = static_cast<uint32_t>(std::sqrt(m_nSieveSize * 8)) + 1000;
    if (primeLimit > 10000000) primeLimit = 10000000;
    m_smallPrimes = GenerateSmallPrimes(primeLimit);

    if (m_smallPrimes.size() > m_nSievePrimes) {
        m_smallPrimes.resize(m_nSievePrimes);
    }

    m_wheelPattern = GenerateWheelPattern(WHEEL_MODULUS);

    LogPrintf("GapcoinMiner: Initialized with %d small primes, wheel size %d\n",
              m_smallPrimes.size(), m_wheelPattern.size());
}

bool GapcoinMiner::StartMining(const CBlockHeader& block, double targetMerit, SolutionCallback callback) {
    if (m_mining.load()) {
        LogPrintf("GapcoinMiner: Already mining\n");
        return false;
    }

    m_blockTemplate = block;
    m_targetMerit = targetMerit;
    m_solutionCallback = callback;
    m_stopRequested = false;
    m_mining = true;
    m_stats.Reset();

    LogPrintf("GapcoinMiner: Starting %d mining threads, target merit %.2f, shift %d\n",
              m_nThreads, targetMerit, m_nShift);

    // Start CPU mining threads
    for (unsigned int i = 0; i < m_nThreads; ++i) {
        m_threads.emplace_back(&GapcoinMiner::MineThread, this, i);
    }

    // Start GPU mining threads for all enabled GPUs
    if (m_gpuBackend != GpuBackend::NONE) {
        for (size_t gpuIdx = 0; gpuIdx < m_gpuContexts.size(); ++gpuIdx) {
            if (m_gpuContexts[gpuIdx]) {
                LogPrintf("GapcoinMiner: Starting GPU %zu mining thread\n", gpuIdx);
                m_threads.emplace_back(&GapcoinMiner::GpuMineThreadMulti, this, gpuIdx);
            }
        }
    }

    return true;
}

void GapcoinMiner::StopMining() {
    if (!m_mining.load()) return;

    LogPrintf("GapcoinMiner: Stopping mining...\n");
    m_stopRequested = true;

    // Signal all GPUs to stop
    for (void* ctx : m_gpuContexts) {
        if (ctx) {
            auto* gpuSieve = static_cast<opencl::GpuSieve*>(ctx);
            gpuSieve->RequestStop();
        }
    }

    // Wait for threads
    for (auto& thread : m_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_threads.clear();

    // Reset GPU stop flags for next mining session
    for (void* ctx : m_gpuContexts) {
        if (ctx) {
            auto* gpuSieve = static_cast<opencl::GpuSieve*>(ctx);
            gpuSieve->ResetStop();
        }
    }

    m_mining = false;
    LogPrintf("GapcoinMiner: Stopped mining\n");
}

GapcoinMiningStats GapcoinMiner::GetStats() const {
    return m_stats.GetSnapshot();
}

void GapcoinMiner::SetProgressCallback(ProgressCallback callback) {
    m_progressCallback = callback;
}

void GapcoinMiner::MineThread(unsigned int threadId) {
    LogPrintf("GapcoinMiner: Thread %d started\n", threadId);

    // Set thread to low priority to keep UI responsive
    SetLowThreadPriority();

    uint64_t adderBase = threadId * (m_nSieveSize * 8);
    uint64_t adderIncrement = m_nThreads * (m_nSieveSize * 8);

    std::vector<uint8_t> sieve(m_nSieveSize, 0);

    auto lastProgressTime = GetTime();
    uint64_t cycleCount = 0;

    while (!m_stopRequested.load()) {
        std::fill(sieve.begin(), sieve.end(), 0);

        SieveSegment(sieve.data(), adderBase, m_nSieveSize);
        FindGaps(sieve.data(), m_nSieveSize, threadId);

        m_stats.sieveCycles++;
        adderBase += adderIncrement;
        cycleCount++;

        // Sleep briefly every cycle to prevent UI starvation
        // 100 microseconds is enough to keep UI responsive
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        auto now = GetTime();
        if (now - lastProgressTime >= 1) {
            if (m_progressCallback) {
                m_progressCallback(m_stats.GetSnapshot());
            }
            lastProgressTime = now;
        }
    }

    LogPrintf("GapcoinMiner: Thread %d stopped\n", threadId);
}

void GapcoinMiner::SieveSegment(uint8_t* sieve, size_t segmentStart, size_t segmentSize) {
    for (size_t i = 0; i < std::min(m_smallPrimes.size(), (size_t)1000); ++i) {
        uint32_t p = m_smallPrimes[i];
        size_t firstMultiple = ((segmentStart / p) + 1) * p - segmentStart;
        if (firstMultiple >= segmentSize * 8) continue;

        for (size_t j = firstMultiple; j < segmentSize * 8; j += p) {
            sieve[j / 8] |= (1 << (j % 8));
        }
    }
}

void GapcoinMiner::FindGaps(const uint8_t* sieve, size_t segmentSize, unsigned int threadId) {
    size_t lastPrimePos = 0;
    bool foundFirstPrime = false;

    for (size_t byte = 0; byte < segmentSize && !m_stopRequested.load(); ++byte) {
        if (sieve[byte] == 0xFF) continue;

        for (int bit = 0; bit < 8; ++bit) {
            if ((sieve[byte] & (1 << bit)) == 0) {
                size_t pos = byte * 8 + bit;

                if (!foundFirstPrime) {
                    lastPrimePos = pos;
                    foundFirstPrime = true;
                    continue;
                }

                size_t gapSize = pos - lastPrimePos;

                if (gapSize > 0) {
                    m_stats.gapsFound++;

                    double lnPrime = (double)m_nShift * std::log(2.0) + std::log((double)pos + 1);
                    double merit = (double)gapSize / lnPrime;

                    double currentBest = m_stats.bestMerit.load();
                    while (merit > currentBest &&
                           !m_stats.bestMerit.compare_exchange_weak(currentBest, merit)) {}

                    if (merit >= m_targetMerit) {
                        GapcoinMiningResult result;
                        result.found = true;
                        result.nShift = m_nShift;
                        result.nGapSize = static_cast<uint32_t>(gapSize);
                        result.merit = merit;
                        result.nAdder.SetNull();

                        LogPrintf("GapcoinMiner: Thread %d found gap! Size=%d, Merit=%.4f\n",
                                  threadId, gapSize, merit);

                        if (m_solutionCallback) {
                            m_solutionCallback(result);
                        }
                    }
                }

                lastPrimePos = pos;
            }
        }
    }

    m_stats.primesChecked += segmentSize * 8;
}

bool GapcoinMiner::EnableGpu(GpuBackend backend, int deviceId) {
    if (backend == GpuBackend::NONE) {
        DisableGpu();
        return true;
    }

    // OpenCL works with both AMD and NVIDIA
    auto& runtime = opencl::OpenCLRuntime::Instance();
    if (!runtime.IsAvailable()) {
        LogPrintf("GapcoinMiner: OpenCL not available on this system\n");
        return false;
    }

    auto devices = runtime.GetGpuDevices();
    if (devices.empty()) {
        LogPrintf("GapcoinMiner: No GPU devices found\n");
        return false;
    }

    if (deviceId >= (int)devices.size()) {
        LogPrintf("GapcoinMiner: Invalid device ID %d (only %zu devices available)\n",
                  deviceId, devices.size());
        return false;
    }

    // Create GPU sieve
    auto gpuSieve = std::make_unique<opencl::GpuSieve>();
    if (!gpuSieve->Initialize(devices[deviceId].platformId, devices[deviceId].deviceId,
                              m_nSieveSize, m_smallPrimes)) {
        LogPrintf("GapcoinMiner: Failed to initialize GPU sieve\n");
        return false;
    }

    m_gpuContext = gpuSieve.release();
    m_gpuBackend = backend;
    m_gpuDeviceId = deviceId;

    LogPrintf("GapcoinMiner: GPU mining enabled on %s\n", devices[deviceId].name.c_str());
    return true;
}

int GapcoinMiner::EnableMultiGpu(GpuBackend backend, const std::vector<int>& deviceIds) {
    if (backend == GpuBackend::NONE || deviceIds.empty()) {
        return 0;
    }

    // First disable any existing GPUs
    DisableGpu();

    auto& runtime = opencl::OpenCLRuntime::Instance();
    if (!runtime.IsAvailable()) {
        LogPrintf("GapcoinMiner: OpenCL not available\n");
        return 0;
    }

    auto devices = runtime.GetGpuDevices();
    if (devices.empty()) {
        LogPrintf("GapcoinMiner: No GPU devices found\n");
        return 0;
    }

    int successCount = 0;
    for (int deviceId : deviceIds) {
        if (deviceId < 0 || deviceId >= (int)devices.size()) {
            LogPrintf("GapcoinMiner: Invalid device ID %d\n", deviceId);
            continue;
        }

        auto gpuSieve = std::make_unique<opencl::GpuSieve>();
        if (gpuSieve->Initialize(devices[deviceId].platformId, devices[deviceId].deviceId,
                                  m_nSieveSize, m_smallPrimes)) {
            m_gpuContexts.push_back(gpuSieve.release());
            m_gpuDeviceIds.push_back(deviceId);
            successCount++;
            LogPrintf("GapcoinMiner: Enabled GPU %d: %s\n", deviceId, devices[deviceId].name.c_str());
        } else {
            LogPrintf("GapcoinMiner: Failed to initialize GPU %d\n", deviceId);
        }
    }

    if (successCount > 0) {
        m_gpuBackend = backend;
        // Keep legacy single GPU pointer for backward compatibility
        m_gpuContext = m_gpuContexts.empty() ? nullptr : m_gpuContexts[0];
        m_gpuDeviceId = m_gpuDeviceIds.empty() ? 0 : m_gpuDeviceIds[0];
    }

    LogPrintf("GapcoinMiner: Enabled %d of %zu requested GPUs\n", successCount, deviceIds.size());
    return successCount;
}

void GapcoinMiner::DisableGpu() {
    // Clean up all GPU contexts
    for (void* ctx : m_gpuContexts) {
        if (ctx) {
            auto* gpuSieve = static_cast<opencl::GpuSieve*>(ctx);
            delete gpuSieve;
        }
    }
    m_gpuContexts.clear();
    m_gpuDeviceIds.clear();

    // Legacy cleanup
    m_gpuContext = nullptr;
    m_gpuBackend = GpuBackend::NONE;
}

bool GapcoinMiner::IsGpuAvailable(GpuBackend backend) {
    if (backend == GpuBackend::NONE) {
        return true;
    }

    auto& runtime = opencl::OpenCLRuntime::Instance();
    if (!runtime.IsAvailable()) {
        return false;
    }

    auto devices = runtime.GetGpuDevices();
    return !devices.empty();
}

std::vector<std::string> GapcoinMiner::GetGpuDevices(GpuBackend backend) {
    std::vector<std::string> result;

    if (backend == GpuBackend::NONE) {
        return result;
    }

    auto& runtime = opencl::OpenCLRuntime::Instance();
    if (!runtime.IsAvailable()) {
        return result;
    }

    auto devices = runtime.GetGpuDevices();
    for (const auto& dev : devices) {
        result.push_back(dev.name + " (" + dev.vendor + ")");
    }

    return result;
}

void GapcoinMiner::GpuMineThread() {
    if (!m_gpuContext) {
        LogPrintf("GapcoinMiner: GPU context not initialized\n");
        return;
    }

    // Set thread to low priority to keep UI responsive
    SetLowThreadPriority();

    auto* gpuSieve = static_cast<opencl::GpuSieve*>(m_gpuContext);
    LogPrintf("GapcoinMiner: GPU mining thread started on %s\n", gpuSieve->GetDeviceName().c_str());

    uint64_t adderBase = m_nThreads * (m_nSieveSize * 8);  // Start after CPU threads
    uint64_t adderIncrement = m_nSieveSize * 8;

    std::vector<uint8_t> sieve(m_nSieveSize, 0);
    auto lastProgressTime = GetTime();

    while (!m_stopRequested.load()) {
        // Use GPU for sieving
        if (!gpuSieve->SieveSegment(adderBase, sieve.data())) {
            LogPrintf("GapcoinMiner: GPU sieve failed, falling back to CPU\n");
            break;
        }

        // Find gaps (currently on CPU, GPU accelerated sieve)
        uint64_t primesChecked = 0;
        uint64_t gapsFound = 0;
        double bestMerit = m_stats.bestMerit.load();

        uint32_t validGap = gpuSieve->FindGaps(sieve.data(), m_nShift, m_targetMerit,
                                               bestMerit, primesChecked, gapsFound);

        // Update stats
        m_stats.primesChecked += primesChecked;
        m_stats.gapsFound += gapsFound;
        m_stats.sieveCycles++;

        // Sleep briefly to prevent UI starvation
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        double currentBest = m_stats.bestMerit.load();
        while (bestMerit > currentBest &&
               !m_stats.bestMerit.compare_exchange_weak(currentBest, bestMerit)) {}

        // Check if found valid gap
        if (validGap > 0) {
            GapcoinMiningResult result;
            result.found = true;
            result.nShift = m_nShift;
            result.nGapSize = validGap;
            result.merit = bestMerit;
            result.nAdder.SetNull();

            LogPrintf("GapcoinMiner: GPU found gap! Size=%d, Merit=%.4f\n", validGap, bestMerit);

            if (m_solutionCallback) {
                m_solutionCallback(result);
            }
        }

        adderBase += adderIncrement;

        auto now = GetTime();
        if (now - lastProgressTime >= 1) {
            if (m_progressCallback) {
                m_progressCallback(m_stats.GetSnapshot());
            }
            lastProgressTime = now;
        }
    }

    LogPrintf("GapcoinMiner: GPU mining thread stopped\n");
}

void GapcoinMiner::GpuMineThreadMulti(size_t gpuIndex) {
    if (gpuIndex >= m_gpuContexts.size() || !m_gpuContexts[gpuIndex]) {
        LogPrintf("GapcoinMiner: Invalid GPU index %zu\n", gpuIndex);
        return;
    }

    // Set thread to low priority to keep UI responsive
    SetLowThreadPriority();

    auto* gpuSieve = static_cast<opencl::GpuSieve*>(m_gpuContexts[gpuIndex]);
    LogPrintf("GapcoinMiner: GPU %zu mining thread started on %s\n", gpuIndex, gpuSieve->GetDeviceName().c_str());

    // Each GPU works on different range
    uint64_t adderBase = (m_nThreads + gpuIndex) * (m_nSieveSize * 8);
    uint64_t adderIncrement = (m_nThreads + m_gpuContexts.size()) * (m_nSieveSize * 8);

    std::vector<uint8_t> sieve(m_nSieveSize, 0);
    auto lastProgressTime = GetTime();

    while (!m_stopRequested.load()) {
        // Check GPU stop flag
        if (gpuSieve->IsStopRequested()) {
            break;
        }

        // Use GPU for sieving
        if (!gpuSieve->SieveSegment(adderBase, sieve.data())) {
            if (gpuSieve->IsStopRequested()) {
                break;  // Normal stop
            }
            LogPrintf("GapcoinMiner: GPU %zu sieve failed\n", gpuIndex);
            break;
        }

        // Find gaps
        uint64_t primesChecked = 0;
        uint64_t gapsFound = 0;
        double bestMerit = m_stats.bestMerit.load();

        uint32_t validGap = gpuSieve->FindGaps(sieve.data(), m_nShift, m_targetMerit,
                                               bestMerit, primesChecked, gapsFound);

        // Update stats
        m_stats.primesChecked += primesChecked;
        m_stats.gapsFound += gapsFound;
        m_stats.sieveCycles++;

        // Sleep briefly to prevent UI starvation
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        double currentBest = m_stats.bestMerit.load();
        while (bestMerit > currentBest &&
               !m_stats.bestMerit.compare_exchange_weak(currentBest, bestMerit)) {}

        // Check if found valid gap
        if (validGap > 0) {
            GapcoinMiningResult result;
            result.found = true;
            result.nShift = m_nShift;
            result.nGapSize = validGap;
            result.merit = bestMerit;
            result.nAdder.SetNull();

            LogPrintf("GapcoinMiner: GPU %zu found gap! Size=%d, Merit=%.4f\n", gpuIndex, validGap, bestMerit);

            if (m_solutionCallback) {
                m_solutionCallback(result);
            }
        }

        adderBase += adderIncrement;

        auto now = GetTime();
        if (now - lastProgressTime >= 1) {
            if (m_progressCallback) {
                m_progressCallback(m_stats.GetSnapshot());
            }
            lastProgressTime = now;
        }
    }

    LogPrintf("GapcoinMiner: GPU %zu mining thread stopped\n", gpuIndex);
}

} // namespace node
