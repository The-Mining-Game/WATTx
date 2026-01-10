// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_OPENCL_RUNTIME_H
#define WATTX_OPENCL_RUNTIME_H

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace opencl {

// OpenCL types (matching official definitions)
typedef intptr_t cl_int;
typedef uintptr_t cl_uint;
typedef uintptr_t cl_ulong;
typedef void* cl_platform_id;
typedef void* cl_device_id;
typedef void* cl_context;
typedef void* cl_command_queue;
typedef void* cl_program;
typedef void* cl_kernel;
typedef void* cl_mem;
typedef cl_ulong cl_device_type;
typedef cl_uint cl_mem_flags;
typedef intptr_t cl_context_properties;

// OpenCL constants
#define CL_SUCCESS 0
#define CL_CONTEXT_PLATFORM 0x1084
#define CL_DEVICE_TYPE_GPU (1 << 2)
#define CL_DEVICE_TYPE_ALL 0xFFFFFFFF
#define CL_MEM_READ_WRITE (1 << 0)
#define CL_MEM_WRITE_ONLY (1 << 1)
#define CL_MEM_READ_ONLY (1 << 2)
#define CL_MEM_COPY_HOST_PTR (1 << 5)

// Device info queries
#define CL_DEVICE_NAME 0x102B
#define CL_DEVICE_VENDOR 0x102C
#define CL_DEVICE_MAX_COMPUTE_UNITS 0x1002
#define CL_DEVICE_MAX_WORK_GROUP_SIZE 0x1004
#define CL_DEVICE_GLOBAL_MEM_SIZE 0x101F

/**
 * GPU Device information
 */
struct GpuDeviceInfo {
    int platformId;
    int deviceId;
    std::string name;
    std::string vendor;
    uint32_t computeUnits;
    size_t maxWorkGroupSize;
    uint64_t globalMemorySize;
};

/**
 * OpenCL Runtime Loader
 *
 * Dynamically loads OpenCL library at runtime to avoid
 * compile-time dependency on OpenCL headers/libraries.
 */
class OpenCLRuntime {
public:
    /**
     * Get singleton instance
     */
    static OpenCLRuntime& Instance();

    /**
     * Check if OpenCL is available on this system
     */
    bool IsAvailable() const { return m_available; }

    /**
     * Get list of available GPU devices
     */
    std::vector<GpuDeviceInfo> GetGpuDevices();

    /**
     * Initialize OpenCL context for a specific device
     * @param platformId Platform index
     * @param deviceId Device index
     * @return true if initialized successfully
     */
    bool Initialize(int platformId, int deviceId);

    /**
     * Check if initialized
     */
    bool IsInitialized() const { return m_initialized; }

    /**
     * Cleanup and release resources
     */
    void Cleanup();

    /**
     * Get current device info
     */
    const GpuDeviceInfo& GetCurrentDevice() const { return m_currentDevice; }

    // OpenCL function pointers (set after loading)
    void* (*clGetPlatformIDs)(cl_uint, cl_platform_id*, cl_uint*);
    void* (*clGetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*);
    void* (*clGetDeviceInfo)(cl_device_id, cl_uint, size_t, void*, size_t*);
    void* (*clCreateContext)(void*, cl_uint, const cl_device_id*, void*, void*, cl_int*);
    void* (*clCreateCommandQueue)(cl_context, cl_device_id, cl_ulong, cl_int*);
    void* (*clCreateProgramWithSource)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
    void* (*clBuildProgram)(cl_program, cl_uint, const cl_device_id*, const char*, void*, void*);
    void* (*clCreateKernel)(cl_program, const char*, cl_int*);
    void* (*clCreateBuffer)(cl_context, cl_mem_flags, size_t, void*, cl_int*);
    void* (*clSetKernelArg)(cl_kernel, cl_uint, size_t, const void*);
    void* (*clEnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, void*, void*);
    void* (*clEnqueueReadBuffer)(cl_command_queue, cl_mem, cl_uint, size_t, size_t, void*, cl_uint, void*, void*);
    void* (*clEnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_uint, size_t, size_t, const void*, cl_uint, void*, void*);
    void* (*clFinish)(cl_command_queue);
    void* (*clReleaseMemObject)(cl_mem);
    void* (*clReleaseKernel)(cl_kernel);
    void* (*clReleaseProgram)(cl_program);
    void* (*clReleaseCommandQueue)(cl_command_queue);
    void* (*clReleaseContext)(cl_context);
    void* (*clGetProgramBuildInfo)(cl_program, cl_device_id, cl_uint, size_t, void*, size_t*);

    // Context and queue accessors
    cl_context GetContext() const { return m_context; }
    cl_command_queue GetQueue() const { return m_queue; }
    cl_device_id GetDevice() const { return m_device; }

private:
    OpenCLRuntime();
    ~OpenCLRuntime();

    bool LoadLibrary();
    void UnloadLibrary();

    void* m_library{nullptr};
    bool m_available{false};
    bool m_initialized{false};

    cl_context m_context{nullptr};
    cl_command_queue m_queue{nullptr};
    cl_device_id m_device{nullptr};
    GpuDeviceInfo m_currentDevice;
};

} // namespace opencl

#endif // WATTX_OPENCL_RUNTIME_H
