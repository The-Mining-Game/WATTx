// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_NODE_GAPCOIN_MINER_H
#define WATTX_NODE_GAPCOIN_MINER_H

#include <primitives/block.h>
#include <uint256.h>
#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include <functional>

#ifdef HAVE_GMP
#include <gmp.h>
#endif

class CChainParams;
class CBlockIndex;

namespace Consensus {
    struct Params;
}

namespace node {

/**
 * Gapcoin Prime Gap Miner
 *
 * Implements a sieve-based algorithm to efficiently find prime gaps:
 * 1. Generate prime candidate: p = sha256(header) * 2^shift + adder
 * 2. Use Sieve of Eratosthenes to mark composites
 * 3. Search for gaps between consecutive primes
 * 4. Find gaps with merit >= target difficulty
 *
 * Optimizations:
 * - Wheel factorization to skip obvious composites
 * - Segmented sieve for cache efficiency
 * - Multi-threaded search across different adder ranges
 * - GPU acceleration via OpenCL/CUDA (optional)
 */

/** Default sieve size in bytes (32MB) */
static constexpr size_t DEFAULT_SIEVE_SIZE = 32 * 1024 * 1024;

/** Number of small primes used for sieving */
static constexpr size_t DEFAULT_SIEVE_PRIMES = 900000;

/** Wheel factorization modulus (2 * 3 * 5 * 7 = 210) */
static constexpr uint32_t WHEEL_MODULUS = 210;

/** Number of residues coprime to WHEEL_MODULUS */
static constexpr uint32_t WHEEL_SIZE = 48;

/**
 * Mining result structure
 */
struct GapcoinMiningResult {
    bool found{false};
    uint32_t nShift{0};
    uint256 nAdder;
    uint32_t nGapSize{0};
    double merit{0.0};

    void SetNull() {
        found = false;
        nShift = 0;
        nAdder.SetNull();
        nGapSize = 0;
        merit = 0.0;
    }
};

/**
 * Mining statistics (snapshot for reporting)
 */
struct GapcoinMiningStats {
    uint64_t primesChecked{0};
    uint64_t gapsFound{0};
    double bestMerit{0.0};
    uint64_t sieveCycles{0};
    uint64_t hashesPerSecond{0};
};

/**
 * Internal atomic stats (used by miner threads)
 */
struct GapcoinMiningStatsAtomic {
    std::atomic<uint64_t> primesChecked{0};
    std::atomic<uint64_t> gapsFound{0};
    std::atomic<double> bestMerit{0.0};
    std::atomic<uint64_t> sieveCycles{0};
    std::atomic<uint64_t> hashesPerSecond{0};

    void Reset() {
        primesChecked = 0;
        gapsFound = 0;
        bestMerit = 0.0;
        sieveCycles = 0;
        hashesPerSecond = 0;
    }

    GapcoinMiningStats GetSnapshot() const {
        GapcoinMiningStats s;
        s.primesChecked = primesChecked.load();
        s.gapsFound = gapsFound.load();
        s.bestMerit = bestMerit.load();
        s.sieveCycles = sieveCycles.load();
        s.hashesPerSecond = hashesPerSecond.load();
        return s;
    }
};

/**
 * GPU mining backend type
 */
enum class GpuBackend {
    NONE,
    OPENCL,
    CUDA
};

/**
 * Gapcoin Miner Class
 *
 * Thread-safe miner for finding prime gaps meeting difficulty requirements.
 */
class GapcoinMiner {
public:
    using ProgressCallback = std::function<void(const GapcoinMiningStats&)>;
    using SolutionCallback = std::function<void(const GapcoinMiningResult&)>;

    /**
     * Constructor
     * @param nThreads Number of mining threads (0 = auto-detect)
     * @param nSieveSize Size of sieve in bytes
     * @param nSievePrimes Number of primes for sieving
     */
    GapcoinMiner(unsigned int nThreads = 0,
                 size_t nSieveSize = DEFAULT_SIEVE_SIZE,
                 size_t nSievePrimes = DEFAULT_SIEVE_PRIMES);

    ~GapcoinMiner();

    // Non-copyable
    GapcoinMiner(const GapcoinMiner&) = delete;
    GapcoinMiner& operator=(const GapcoinMiner&) = delete;

    /**
     * Start mining for a block
     * @param block Block template to mine
     * @param targetMerit Target merit (difficulty)
     * @param callback Callback when solution found
     * @return true if mining started successfully
     */
    bool StartMining(const CBlockHeader& block,
                     double targetMerit,
                     SolutionCallback callback);

    /**
     * Stop all mining threads
     */
    void StopMining();

    /**
     * Check if currently mining
     */
    bool IsMining() const { return m_mining.load(); }

    /**
     * Get current mining statistics
     */
    GapcoinMiningStats GetStats() const;

    /**
     * Set progress callback (called periodically)
     */
    void SetProgressCallback(ProgressCallback callback);

    /**
     * Configure GPU mining (if available)
     * @param backend GPU backend to use
     * @param deviceId GPU device ID
     * @return true if GPU initialized successfully
     */
    bool EnableGpu(GpuBackend backend, int deviceId = 0);

    /**
     * Disable GPU mining
     */
    void DisableGpu();

    /**
     * Check if GPU mining is available
     */
    static bool IsGpuAvailable(GpuBackend backend);

    /**
     * Get list of available GPU devices
     */
    static std::vector<std::string> GetGpuDevices(GpuBackend backend);

    /**
     * Set shift value for mining
     * @param nShift Shift value (controls prime magnitude)
     */
    void SetShift(uint32_t nShift) { m_nShift = nShift; }

    /**
     * Get current shift value
     */
    uint32_t GetShift() const { return m_nShift; }

private:
    // Mining thread function
    void MineThread(unsigned int threadId);

    // Initialize sieve of small primes
    void InitializeSieve();

    // Sieve a segment for composites
    void SieveSegment(uint8_t* sieve, size_t segmentStart, size_t segmentSize);

    // Find prime gaps in a sieved segment
    void FindGaps(const uint8_t* sieve, size_t segmentSize,
                  unsigned int threadId);

#ifdef HAVE_GMP
    // Calculate the base prime candidate from block header
    void CalculateBasePrime(mpz_t result);

    // Verify a found gap is valid
    bool VerifyGap(const mpz_t startPrime, uint32_t gapSize, double& merit);
#endif

    // Member variables
    unsigned int m_nThreads;
    size_t m_nSieveSize;
    size_t m_nSievePrimes;
    uint32_t m_nShift{25};  // Default shift

    std::atomic<bool> m_mining{false};
    std::atomic<bool> m_stopRequested{false};

    std::vector<std::thread> m_threads;
    std::vector<uint32_t> m_smallPrimes;  // Small primes for sieving
    std::vector<uint8_t> m_wheelPattern;  // Wheel factorization pattern

    CBlockHeader m_blockTemplate;
    double m_targetMerit{0.0};

    GapcoinMiningStatsAtomic m_stats;
    SolutionCallback m_solutionCallback;
    ProgressCallback m_progressCallback;

    // GPU mining state
    GpuBackend m_gpuBackend{GpuBackend::NONE};
    int m_gpuDeviceId{0};
    void* m_gpuContext{nullptr};  // Opaque GPU context
};

/**
 * Generate a list of small primes up to a limit
 * @param limit Upper bound
 * @return Vector of primes
 */
std::vector<uint32_t> GenerateSmallPrimes(uint32_t limit);

/**
 * Generate wheel factorization pattern
 * @param modulus Wheel modulus (e.g., 210 = 2*3*5*7)
 * @return Vector of residues coprime to modulus
 */
std::vector<uint8_t> GenerateWheelPattern(uint32_t modulus);

} // namespace node

#endif // WATTX_NODE_GAPCOIN_MINER_H
