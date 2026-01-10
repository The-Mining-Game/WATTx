// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <opencl/gpu_sieve.h>
#include <opencl/sieve_kernel.h>
#include <logging.h>
#include <cmath>
#include <cstring>

namespace opencl {

GpuSieve::GpuSieve() : m_runtime(OpenCLRuntime::Instance()) {
}

GpuSieve::~GpuSieve() {
    Cleanup();
}

bool GpuSieve::Initialize(int platformId, int deviceId, size_t sieveSize,
                          const std::vector<uint32_t>& primes) {
    if (m_initialized) {
        Cleanup();
    }

    if (!m_runtime.IsAvailable()) {
        LogPrintf("GpuSieve: OpenCL not available\n");
        return false;
    }

    // Initialize OpenCL context
    if (!m_runtime.IsInitialized()) {
        if (!m_runtime.Initialize(platformId, deviceId)) {
            LogPrintf("GpuSieve: Failed to initialize OpenCL\n");
            return false;
        }
    }

    // Use smaller sieve for GPU to allow faster stop response
    // Max 4MB sieve for GPU (vs 32MB default for CPU)
    m_sieveSize = std::min(sieveSize, (size_t)(4 * 1024 * 1024));
    m_numPrimes = primes.size();

    // Get max work group size
    auto& dev = m_runtime.GetCurrentDevice();
    m_maxWorkGroupSize = dev.maxWorkGroupSize > 0 ? dev.maxWorkGroupSize : 256;
    if (m_maxWorkGroupSize > 256) m_maxWorkGroupSize = 256;

    // Compile kernel
    if (!CompileKernel()) {
        return false;
    }

    // Create GPU buffers
    cl_int err;
    auto ctx = m_runtime.GetContext();

    // Sieve buffer
    m_sieveBuffer = (cl_mem)(intptr_t)m_runtime.clCreateBuffer(
        ctx, CL_MEM_READ_WRITE, m_sieveSize, nullptr, &err);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to create sieve buffer (err=%d)\n", err);
        return false;
    }

    // Primes buffer
    m_primesBuffer = (cl_mem)(intptr_t)m_runtime.clCreateBuffer(
        ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
        primes.size() * sizeof(uint32_t), (void*)primes.data(), &err);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to create primes buffer (err=%d)\n", err);
        return false;
    }

    // Gap output buffers
    m_gapsBuffer = (cl_mem)(intptr_t)m_runtime.clCreateBuffer(
        ctx, CL_MEM_WRITE_ONLY, 65536 * sizeof(uint32_t), nullptr, &err);
    m_primePositionsBuffer = (cl_mem)(intptr_t)m_runtime.clCreateBuffer(
        ctx, CL_MEM_WRITE_ONLY, 65536 * sizeof(uint32_t), nullptr, &err);
    m_gapCountBuffer = (cl_mem)(intptr_t)m_runtime.clCreateBuffer(
        ctx, CL_MEM_READ_WRITE, sizeof(uint32_t), nullptr, &err);
    m_countBuffer = (cl_mem)(intptr_t)m_runtime.clCreateBuffer(
        ctx, CL_MEM_READ_WRITE, sizeof(uint32_t), nullptr, &err);

    m_initialized = true;
    LogPrintf("GpuSieve: Initialized on %s with %zu primes, %zu KB sieve\n",
             GetDeviceName().c_str(), m_numPrimes, m_sieveSize / 1024);

    return true;
}

bool GpuSieve::CompileKernel() {
    cl_int err;
    auto ctx = m_runtime.GetContext();
    auto dev = m_runtime.GetDevice();

    // Create program
    const char* source = SIEVE_KERNEL_SOURCE;
    size_t sourceLen = strlen(source);

    m_program = (cl_program)(intptr_t)m_runtime.clCreateProgramWithSource(
        ctx, 1, &source, &sourceLen, &err);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to create program (err=%d)\n", err);
        return false;
    }

    // Build program
    err = (cl_int)(intptr_t)m_runtime.clBuildProgram(
        m_program, 1, &dev, "-cl-fast-relaxed-math", nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // Get build log
        size_t logSize;
        m_runtime.clGetProgramBuildInfo(m_program, dev, 0x1183 /*CL_PROGRAM_BUILD_LOG*/,
                                        0, nullptr, &logSize);
        if (logSize > 0) {
            std::vector<char> log(logSize);
            m_runtime.clGetProgramBuildInfo(m_program, dev, 0x1183,
                                           logSize, log.data(), nullptr);
            LogPrintf("GpuSieve: Build failed: %s\n", log.data());
        }
        return false;
    }

    // Create kernels
    m_sieveKernel = (cl_kernel)(intptr_t)m_runtime.clCreateKernel(
        m_program, "sieve_segment", &err);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to create sieve kernel (err=%d)\n", err);
        return false;
    }

    m_gapKernel = (cl_kernel)(intptr_t)m_runtime.clCreateKernel(
        m_program, "find_gaps", &err);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to create gap kernel (err=%d)\n", err);
        return false;
    }

    m_countKernel = (cl_kernel)(intptr_t)m_runtime.clCreateKernel(
        m_program, "count_primes", &err);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to create count kernel (err=%d)\n", err);
        return false;
    }

    LogPrintf("GpuSieve: Kernels compiled successfully\n");
    return true;
}

bool GpuSieve::SieveSegment(uint64_t segmentStart, uint8_t* hostSieve) {
    if (!m_initialized) return false;
    if (m_stopRequested) return false;

    auto queue = m_runtime.GetQueue();
    cl_int err;

    // Clear sieve buffer on GPU (non-blocking)
    std::vector<uint8_t> zeros(m_sieveSize, 0);
    err = (cl_int)(intptr_t)m_runtime.clEnqueueWriteBuffer(
        queue, m_sieveBuffer, 0 /*non-blocking*/, 0, m_sieveSize,
        zeros.data(), 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to clear sieve (err=%d)\n", err);
        return false;
    }

    // Check stop before kernel launch
    if (m_stopRequested) {
        m_runtime.clFinish(queue);
        return false;
    }

    // Set kernel arguments
    cl_uint sieveSizeArg = (cl_uint)m_sieveSize;
    cl_uint numPrimesArg = (cl_uint)std::min(m_numPrimes, (size_t)10000);  // Limit primes for faster response

    m_runtime.clSetKernelArg(m_sieveKernel, 0, sizeof(cl_mem), &m_sieveBuffer);
    m_runtime.clSetKernelArg(m_sieveKernel, 1, sizeof(cl_mem), &m_primesBuffer);
    m_runtime.clSetKernelArg(m_sieveKernel, 2, sizeof(uint64_t), &segmentStart);
    m_runtime.clSetKernelArg(m_sieveKernel, 3, sizeof(cl_uint), &sieveSizeArg);
    m_runtime.clSetKernelArg(m_sieveKernel, 4, sizeof(cl_uint), &numPrimesArg);

    // Launch kernel - one work item per small prime
    size_t globalSize = ((numPrimesArg + m_maxWorkGroupSize - 1) / m_maxWorkGroupSize) * m_maxWorkGroupSize;
    size_t localSize = m_maxWorkGroupSize;

    err = (cl_int)(intptr_t)m_runtime.clEnqueueNDRangeKernel(
        queue, m_sieveKernel, 1, nullptr, &globalSize, &localSize,
        0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to launch sieve kernel (err=%d)\n", err);
        return false;
    }

    // Wait for completion (required before reading)
    m_runtime.clFinish(queue);

    // Check stop before reading back
    if (m_stopRequested) {
        return false;
    }

    // Read back sieve to host (non-blocking)
    err = (cl_int)(intptr_t)m_runtime.clEnqueueReadBuffer(
        queue, m_sieveBuffer, 0 /*non-blocking*/, 0, m_sieveSize,
        hostSieve, 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        LogPrintf("GpuSieve: Failed to read sieve (err=%d)\n", err);
        return false;
    }

    // Final sync
    m_runtime.clFinish(queue);

    return !m_stopRequested;
}

uint32_t GpuSieve::FindGaps(const uint8_t* hostSieve, uint32_t shift,
                            double targetMerit, double& bestMerit,
                            uint64_t& primesChecked, uint64_t& gapsFound) {
    // Find gaps on CPU for now (GPU gap finding is complex due to sequential nature)
    // The GPU accelerates the sieving, CPU does the gap analysis

    size_t lastPrimePos = 0;
    bool foundFirstPrime = false;
    uint32_t validGap = 0;

    for (size_t byte = 0; byte < m_sieveSize; ++byte) {
        if (hostSieve[byte] == 0xFF) continue;

        for (int bit = 0; bit < 8; ++bit) {
            if ((hostSieve[byte] & (1 << bit)) == 0) {
                size_t pos = byte * 8 + bit;

                if (!foundFirstPrime) {
                    lastPrimePos = pos;
                    foundFirstPrime = true;
                    continue;
                }

                size_t gapSize = pos - lastPrimePos;

                if (gapSize > 0) {
                    gapsFound++;

                    // Calculate merit
                    double lnPrime = (double)shift * std::log(2.0) + std::log((double)pos + 1);
                    double merit = (double)gapSize / lnPrime;

                    if (merit > bestMerit) {
                        bestMerit = merit;
                    }

                    if (merit >= targetMerit && validGap == 0) {
                        validGap = static_cast<uint32_t>(gapSize);
                    }
                }

                lastPrimePos = pos;
            }
        }
    }

    primesChecked += m_sieveSize * 8;
    return validGap;
}

void GpuSieve::Cleanup() {
    if (m_sieveBuffer) {
        m_runtime.clReleaseMemObject(m_sieveBuffer);
        m_sieveBuffer = nullptr;
    }
    if (m_primesBuffer) {
        m_runtime.clReleaseMemObject(m_primesBuffer);
        m_primesBuffer = nullptr;
    }
    if (m_gapsBuffer) {
        m_runtime.clReleaseMemObject(m_gapsBuffer);
        m_gapsBuffer = nullptr;
    }
    if (m_primePositionsBuffer) {
        m_runtime.clReleaseMemObject(m_primePositionsBuffer);
        m_primePositionsBuffer = nullptr;
    }
    if (m_gapCountBuffer) {
        m_runtime.clReleaseMemObject(m_gapCountBuffer);
        m_gapCountBuffer = nullptr;
    }
    if (m_countBuffer) {
        m_runtime.clReleaseMemObject(m_countBuffer);
        m_countBuffer = nullptr;
    }
    if (m_sieveKernel) {
        m_runtime.clReleaseKernel(m_sieveKernel);
        m_sieveKernel = nullptr;
    }
    if (m_gapKernel) {
        m_runtime.clReleaseKernel(m_gapKernel);
        m_gapKernel = nullptr;
    }
    if (m_countKernel) {
        m_runtime.clReleaseKernel(m_countKernel);
        m_countKernel = nullptr;
    }
    if (m_program) {
        m_runtime.clReleaseProgram(m_program);
        m_program = nullptr;
    }

    m_initialized = false;
}

std::string GpuSieve::GetDeviceName() const {
    if (m_runtime.IsInitialized()) {
        return m_runtime.GetCurrentDevice().name;
    }
    return "Unknown";
}

} // namespace opencl
