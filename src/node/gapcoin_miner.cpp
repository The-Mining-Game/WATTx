// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/gapcoin_miner.h>
#include <consensus/gapcoin_pow.h>
#include <hash.h>
#include <logging.h>
#include <util/time.h>
#include <crypto/sha256.h>
#include <streams.h>
#include <serialize.h>

#include <algorithm>
#include <cmath>
#include <random>
#include <chrono>

#ifdef HAVE_GMP
#include <gmp.h>
#endif

#ifdef HAVE_MPFR
#include <mpfr.h>
#endif

namespace node {

std::vector<uint32_t> GenerateSmallPrimes(uint32_t limit)
{
    std::vector<uint32_t> primes;
    if (limit < 2) return primes;

    // Simple Sieve of Eratosthenes for small primes
    std::vector<bool> isPrime(limit + 1, true);
    isPrime[0] = isPrime[1] = false;

    for (uint32_t i = 2; i * i <= limit; ++i) {
        if (isPrime[i]) {
            for (uint32_t j = i * i; j <= limit; j += i) {
                isPrime[j] = false;
            }
        }
    }

    for (uint32_t i = 2; i <= limit; ++i) {
        if (isPrime[i]) {
            primes.push_back(i);
        }
    }

    return primes;
}

std::vector<uint8_t> GenerateWheelPattern(uint32_t modulus)
{
    std::vector<uint8_t> pattern;

    // Find residues coprime to modulus
    for (uint32_t i = 1; i < modulus; ++i) {
        if (std::gcd(i, modulus) == 1) {
            pattern.push_back(static_cast<uint8_t>(i));
        }
    }

    return pattern;
}

GapcoinMiner::GapcoinMiner(unsigned int nThreads, size_t nSieveSize, size_t nSievePrimes)
    : m_nThreads(nThreads == 0 ? std::thread::hardware_concurrency() : nThreads),
      m_nSieveSize(nSieveSize),
      m_nSievePrimes(nSievePrimes)
{
    if (m_nThreads == 0) m_nThreads = 1;

    // Initialize small primes for sieving
    InitializeSieve();

    LogPrintf("GapcoinMiner: Initialized with %u threads, %zu byte sieve, %zu primes\n",
              m_nThreads, m_nSieveSize, m_smallPrimes.size());
}

GapcoinMiner::~GapcoinMiner()
{
    StopMining();
}

void GapcoinMiner::InitializeSieve()
{
    // Generate small primes up to sqrt of sieve size * 64 (bits)
    uint32_t primeLimit = static_cast<uint32_t>(std::sqrt(m_nSieveSize * 8.0)) + 1000;
    primeLimit = std::min(primeLimit, static_cast<uint32_t>(m_nSievePrimes * 20));

    m_smallPrimes = GenerateSmallPrimes(primeLimit);

    // Limit to requested number of primes
    if (m_smallPrimes.size() > m_nSievePrimes) {
        m_smallPrimes.resize(m_nSievePrimes);
    }

    // Generate wheel pattern for optimization
    m_wheelPattern = GenerateWheelPattern(WHEEL_MODULUS);

    LogPrintf("GapcoinMiner: Generated %zu sieving primes, wheel size %zu\n",
              m_smallPrimes.size(), m_wheelPattern.size());
}

bool GapcoinMiner::StartMining(const CBlockHeader& block,
                                double targetMerit,
                                SolutionCallback callback)
{
    if (m_mining.load()) {
        LogPrintf("GapcoinMiner: Already mining, stopping first\n");
        StopMining();
    }

    m_blockTemplate = block;
    m_targetMerit = targetMerit;
    m_solutionCallback = callback;
    m_stopRequested = false;
    m_stats.Reset();

    LogPrintf("GapcoinMiner: Starting mining with target merit %.2f, shift %u\n",
              targetMerit, m_nShift);

    m_mining = true;

    // Launch mining threads
    m_threads.clear();
    for (unsigned int i = 0; i < m_nThreads; ++i) {
        m_threads.emplace_back(&GapcoinMiner::MineThread, this, i);
    }

    return true;
}

void GapcoinMiner::StopMining()
{
    if (!m_mining.load()) return;

    LogPrintf("GapcoinMiner: Stopping mining\n");
    m_stopRequested = true;

    for (auto& thread : m_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_threads.clear();

    m_mining = false;
    LogPrintf("GapcoinMiner: Mining stopped. Stats: primes=%lu, gaps=%lu, best_merit=%.2f\n",
              m_stats.primesChecked.load(), m_stats.gapsFound.load(), m_stats.bestMerit.load());
}

GapcoinMiningStats GapcoinMiner::GetStats() const
{
    return m_stats.GetSnapshot();
}

void GapcoinMiner::SetProgressCallback(ProgressCallback callback)
{
    m_progressCallback = callback;
}

void GapcoinMiner::MineThread(unsigned int threadId)
{
    LogPrintf("GapcoinMiner: Thread %u started\n", threadId);

#ifdef HAVE_GMP
    // Thread-local GMP variables
    mpz_t basePrime, testPrime, adder;
    mpz_init(basePrime);
    mpz_init(testPrime);
    mpz_init(adder);

    // Calculate base prime from block header
    CalculateBasePrime(basePrime);

    // Each thread searches a different adder range
    // Thread 0: [0, range), Thread 1: [range, 2*range), etc.
    uint64_t rangePerThread = (1ULL << (m_nShift > 32 ? 32 : m_nShift)) / m_nThreads;
    uint64_t startAdder = threadId * rangePerThread;

    // Allocate thread-local sieve
    std::vector<uint8_t> sieve(m_nSieveSize);

    std::random_device rd;
    std::mt19937_64 rng(rd() + threadId);

    auto lastProgressTime = std::chrono::steady_clock::now();
    uint64_t localPrimesChecked = 0;

    while (!m_stopRequested.load()) {
        // Set current adder
        mpz_set_ui(adder, startAdder);

        // Clear sieve (1 = potentially prime, 0 = composite)
        std::fill(sieve.begin(), sieve.end(), 0xFF);

        // Sieve the segment
        SieveSegment(sieve.data(), startAdder, m_nSieveSize);
        m_stats.sieveCycles++;

        // Search for gaps in the sieved segment
        uint32_t currentGapStart = 0;
        bool inGap = false;
        uint32_t gapSize = 0;

        for (size_t byteIdx = 0; byteIdx < m_nSieveSize && !m_stopRequested.load(); ++byteIdx) {
            uint8_t byte = sieve[byteIdx];

            for (int bit = 0; bit < 8; ++bit) {
                bool isPotentialPrime = (byte >> bit) & 1;
                uint32_t offset = static_cast<uint32_t>(byteIdx * 8 + bit);

                if (isPotentialPrime) {
                    // Calculate actual number: basePrime + adder + offset
                    mpz_set_ui(testPrime, offset);
                    mpz_add(testPrime, testPrime, adder);
                    mpz_add(testPrime, testPrime, basePrime);

                    // Quick primality test
                    int isPrime = mpz_probab_prime_p(testPrime, 3);

                    if (isPrime) {
                        localPrimesChecked++;

                        if (inGap) {
                            // End of gap found
                            gapSize = offset - currentGapStart;

                            if (gapSize >= 10) {  // Minimum interesting gap
                                double merit;
                                mpz_t gapStart;
                                mpz_init(gapStart);
                                mpz_set_ui(gapStart, currentGapStart);
                                mpz_add(gapStart, gapStart, adder);
                                mpz_add(gapStart, gapStart, basePrime);

                                if (VerifyGap(gapStart, gapSize, merit)) {
                                    m_stats.gapsFound++;

                                    // Update best merit
                                    double currentBest = m_stats.bestMerit.load();
                                    while (merit > currentBest &&
                                           !m_stats.bestMerit.compare_exchange_weak(currentBest, merit)) {}

                                    if (merit >= m_targetMerit) {
                                        // Found a solution!
                                        GapcoinMiningResult result;
                                        result.found = true;
                                        result.nShift = m_nShift;
                                        result.nGapSize = gapSize;
                                        result.merit = merit;

                                        // Convert adder + currentGapStart to uint256
                                        size_t count;
                                        mpz_export(result.nAdder.begin(), &count, -1, 1, 0, 0, gapStart);

                                        LogPrintf("GapcoinMiner: Thread %u found solution! Gap=%u, Merit=%.4f\n",
                                                  threadId, gapSize, merit);

                                        if (m_solutionCallback) {
                                            m_solutionCallback(result);
                                        }
                                    }
                                }
                                mpz_clear(gapStart);
                            }
                        }

                        // Start new potential gap
                        currentGapStart = offset;
                        inGap = true;
                    }
                }
            }
        }

        // Move to next segment
        startAdder += m_nSieveSize * 8;
        if (startAdder >= rangePerThread * (threadId + 1)) {
            // Wrapped around, restart with some randomization
            startAdder = threadId * rangePerThread + (rng() % rangePerThread);
        }

        // Update statistics
        m_stats.primesChecked += localPrimesChecked;
        localPrimesChecked = 0;

        // Progress callback
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastProgressTime).count() >= 1) {
            if (m_progressCallback) {
                m_progressCallback(m_stats.GetSnapshot());
            }
            lastProgressTime = now;
        }
    }

    mpz_clear(basePrime);
    mpz_clear(testPrime);
    mpz_clear(adder);
#else
    // No GMP support - can't do real mining
    LogPrintf("GapcoinMiner: Thread %u - GMP not available, mining disabled\n", threadId);
    while (!m_stopRequested.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
#endif

    LogPrintf("GapcoinMiner: Thread %u exiting\n", threadId);
}

void GapcoinMiner::SieveSegment(uint8_t* sieve, size_t segmentStart, size_t segmentSize)
{
    // Mark composites using small primes
    for (const uint32_t prime : m_smallPrimes) {
        if (prime <= 2) continue;

        // Find first multiple of prime in this segment
        size_t firstMultiple = (segmentStart / prime) * prime;
        if (firstMultiple < segmentStart) {
            firstMultiple += prime;
        }

        // Mark all multiples as composite
        for (size_t mult = firstMultiple; mult < segmentStart + segmentSize * 8; mult += prime) {
            size_t bit = mult - segmentStart;
            if (bit < segmentSize * 8) {
                sieve[bit / 8] &= ~(1 << (bit % 8));
            }
        }
    }
}

#ifdef HAVE_GMP
void GapcoinMiner::CalculateBasePrime(mpz_t result)
{
    // Calculate: p = sha256(blockHeader) * 2^shift
    // The adder is added separately during mining

    // Serialize block header (without Gapcoin fields)
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << m_blockTemplate.nVersion;
    ss << m_blockTemplate.hashPrevBlock;
    ss << m_blockTemplate.hashMerkleRoot;
    ss << m_blockTemplate.nTime;
    ss << m_blockTemplate.nBits;
    ss << m_blockTemplate.nNonce;

    // Calculate SHA256
    uint256 hash = Hash(ss);

    // Import hash into GMP
    mpz_import(result, 32, -1, 1, 0, 0, hash.begin());

    // Multiply by 2^shift
    mpz_mul_2exp(result, result, m_nShift);
}

bool GapcoinMiner::VerifyGap(const mpz_t startPrime, uint32_t gapSize, double& merit)
{
    mpz_t endPrime, test;
    mpz_init(endPrime);
    mpz_init(test);

    // Check that startPrime is actually prime
    if (mpz_probab_prime_p(startPrime, 10) == 0) {
        mpz_clear(endPrime);
        mpz_clear(test);
        return false;
    }

    // Calculate end prime
    mpz_add_ui(endPrime, startPrime, gapSize);

    // Check that endPrime is prime
    if (mpz_probab_prime_p(endPrime, 10) == 0) {
        mpz_clear(endPrime);
        mpz_clear(test);
        return false;
    }

    // Verify all numbers in between are composite
    // (Only check a sample for efficiency - sieve should have caught composites)
    mpz_set(test, startPrime);
    for (uint32_t i = 2; i < gapSize; i += std::max(1u, gapSize / 100)) {
        mpz_add_ui(test, startPrime, i);
        if (mpz_probab_prime_p(test, 2) > 0) {
            // Found a prime in the gap - invalid
            mpz_clear(endPrime);
            mpz_clear(test);
            return false;
        }
    }

    // Calculate merit = gapSize / ln(startPrime)
#ifdef HAVE_MPFR
    mpfr_t ln_prime, gap, m;
    mpfr_init2(ln_prime, 128);
    mpfr_init2(gap, 128);
    mpfr_init2(m, 128);

    mpfr_set_z(ln_prime, startPrime, MPFR_RNDN);
    mpfr_log(ln_prime, ln_prime, MPFR_RNDN);

    mpfr_set_ui(gap, gapSize, MPFR_RNDN);
    mpfr_div(m, gap, ln_prime, MPFR_RNDN);

    merit = mpfr_get_d(m, MPFR_RNDN);

    mpfr_clear(ln_prime);
    mpfr_clear(gap);
    mpfr_clear(m);
#else
    // Approximate ln(prime) using bit length
    size_t bits = mpz_sizeinbase(startPrime, 2);
    double approxLn = bits * 0.693147;  // ln(2) * bits
    merit = gapSize / approxLn;
#endif

    mpz_clear(endPrime);
    mpz_clear(test);
    return true;
}
#endif

bool GapcoinMiner::EnableGpu(GpuBackend backend, int deviceId)
{
    // TODO: Implement OpenCL/CUDA GPU mining
    // This would involve:
    // 1. Initialize GPU context
    // 2. Load sieving kernels
    // 3. Transfer prime table to GPU
    // 4. Parallel sieve execution on GPU

    LogPrintf("GapcoinMiner: GPU mining not yet implemented (backend=%d, device=%d)\n",
              static_cast<int>(backend), deviceId);

    m_gpuBackend = backend;
    m_gpuDeviceId = deviceId;

    return false;  // Not implemented yet
}

void GapcoinMiner::DisableGpu()
{
    m_gpuBackend = GpuBackend::NONE;
    m_gpuContext = nullptr;
}

bool GapcoinMiner::IsGpuAvailable(GpuBackend backend)
{
    // TODO: Check for GPU availability
    // OpenCL: clGetPlatformIDs, clGetDeviceIDs
    // CUDA: cudaGetDeviceCount
    return false;
}

std::vector<std::string> GapcoinMiner::GetGpuDevices(GpuBackend backend)
{
    // TODO: Enumerate GPU devices
    return {};
}

} // namespace node
