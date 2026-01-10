// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_OPENCL_GPU_SIEVE_H
#define WATTX_OPENCL_GPU_SIEVE_H

#include <opencl/opencl_runtime.h>
#include <cstdint>
#include <vector>
#include <atomic>
#include <functional>

namespace opencl {

/**
 * GPU-accelerated prime sieve using OpenCL
 *
 * Works with both AMD and NVIDIA GPUs through OpenCL.
 */
class GpuSieve {
public:
    using ProgressCallback = std::function<void(uint64_t primesChecked, uint64_t gapsFound, double bestMerit)>;

    GpuSieve();
    ~GpuSieve();

    /**
     * Initialize GPU sieve
     * @param platformId OpenCL platform index
     * @param deviceId OpenCL device index
     * @param sieveSize Size of sieve in bytes
     * @param primes Vector of small primes for sieving
     * @return true if initialized successfully
     */
    bool Initialize(int platformId, int deviceId, size_t sieveSize,
                   const std::vector<uint32_t>& primes);

    /**
     * Check if initialized
     */
    bool IsInitialized() const { return m_initialized; }

    /**
     * Run sieve on GPU for one segment
     * @param segmentStart Start offset of segment
     * @param hostSieve Output sieve buffer (CPU memory)
     * @return true if successful
     */
    bool SieveSegment(uint64_t segmentStart, uint8_t* hostSieve);

    /**
     * Find gaps in sieved segment
     * @param hostSieve Sieve buffer
     * @param shift Mining shift value
     * @param targetMerit Target merit for valid gap
     * @param bestMerit Output: best merit found
     * @param primesChecked Output: number of primes checked
     * @param gapsFound Output: number of gaps found
     * @return Gap size if found valid gap, 0 otherwise
     */
    uint32_t FindGaps(const uint8_t* hostSieve, uint32_t shift,
                      double targetMerit, double& bestMerit,
                      uint64_t& primesChecked, uint64_t& gapsFound);

    /**
     * Cleanup GPU resources
     */
    void Cleanup();

    /**
     * Get device name
     */
    std::string GetDeviceName() const;

    /**
     * Request stop - makes SieveSegment return early
     */
    void RequestStop() { m_stopRequested = true; }

    /**
     * Reset stop flag
     */
    void ResetStop() { m_stopRequested = false; }

    /**
     * Check if stop was requested
     */
    bool IsStopRequested() const { return m_stopRequested; }

private:
    bool CompileKernel();

    OpenCLRuntime& m_runtime;
    bool m_initialized{false};
    bool m_stopRequested{false};
    size_t m_sieveSize{0};

    // OpenCL objects
    cl_program m_program{nullptr};
    cl_kernel m_sieveKernel{nullptr};
    cl_kernel m_gapKernel{nullptr};
    cl_kernel m_countKernel{nullptr};

    // GPU buffers
    cl_mem m_sieveBuffer{nullptr};
    cl_mem m_primesBuffer{nullptr};
    cl_mem m_gapsBuffer{nullptr};
    cl_mem m_primePositionsBuffer{nullptr};
    cl_mem m_gapCountBuffer{nullptr};
    cl_mem m_countBuffer{nullptr};

    size_t m_numPrimes{0};
    size_t m_maxWorkGroupSize{256};
};

} // namespace opencl

#endif // WATTX_OPENCL_GPU_SIEVE_H
