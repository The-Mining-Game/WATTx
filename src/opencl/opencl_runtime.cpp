// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <opencl/opencl_runtime.h>
#include <logging.h>

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace opencl {

OpenCLRuntime& OpenCLRuntime::Instance() {
    static OpenCLRuntime instance;
    return instance;
}

OpenCLRuntime::OpenCLRuntime() {
    m_available = LoadOpenCLLib();
    if (m_available) {
        LogPrintf("OpenCL: Library loaded successfully\n");
    } else {
        LogPrintf("OpenCL: Library not available\n");
    }
}

OpenCLRuntime::~OpenCLRuntime() {
    Cleanup();
    UnloadOpenCLLib();
}

bool OpenCLRuntime::LoadOpenCLLib() {
#ifdef WIN32
    m_library = ::LoadLibraryA("OpenCL.dll");
    if (!m_library) {
        m_library = ::LoadLibraryA("C:\\Windows\\System32\\OpenCL.dll");
    }
#else
    // Try common library paths
    const char* libNames[] = {
        "libOpenCL.so.1",
        "libOpenCL.so",
        "/usr/lib/x86_64-linux-gnu/libOpenCL.so.1",
        "/usr/lib64/libOpenCL.so.1",
        "/opt/cuda/lib64/libOpenCL.so.1",
        nullptr
    };

    for (int i = 0; libNames[i] != nullptr; ++i) {
        m_library = dlopen(libNames[i], RTLD_NOW);
        if (m_library) {
            LogPrintf("OpenCL: Loaded %s\n", libNames[i]);
            break;
        }
    }
#endif

    if (!m_library) {
        return false;
    }

    // Load function pointers
#ifdef WIN32
    #define LOAD_FUNC(name) name = (decltype(name))GetProcAddress((HMODULE)m_library, #name)
#else
    #define LOAD_FUNC(name) name = (decltype(name))dlsym(m_library, #name)
#endif

    LOAD_FUNC(clGetPlatformIDs);
    LOAD_FUNC(clGetDeviceIDs);
    LOAD_FUNC(clGetDeviceInfo);
    LOAD_FUNC(clCreateContext);
    LOAD_FUNC(clCreateCommandQueue);
    LOAD_FUNC(clCreateProgramWithSource);
    LOAD_FUNC(clBuildProgram);
    LOAD_FUNC(clCreateKernel);
    LOAD_FUNC(clCreateBuffer);
    LOAD_FUNC(clSetKernelArg);
    LOAD_FUNC(clEnqueueNDRangeKernel);
    LOAD_FUNC(clEnqueueReadBuffer);
    LOAD_FUNC(clEnqueueWriteBuffer);
    LOAD_FUNC(clFinish);
    LOAD_FUNC(clReleaseMemObject);
    LOAD_FUNC(clReleaseKernel);
    LOAD_FUNC(clReleaseProgram);
    LOAD_FUNC(clReleaseCommandQueue);
    LOAD_FUNC(clReleaseContext);
    LOAD_FUNC(clGetProgramBuildInfo);

#undef LOAD_FUNC

    // Check required functions
    if (!clGetPlatformIDs || !clGetDeviceIDs || !clCreateContext ||
        !clCreateCommandQueue || !clCreateProgramWithSource) {
        LogPrintf("OpenCL: Failed to load required functions\n");
        UnloadOpenCLLib();
        return false;
    }

    return true;
}

void OpenCLRuntime::UnloadOpenCLLib() {
    if (m_library) {
#ifdef WIN32
        ::FreeLibrary((HMODULE)m_library);
#else
        dlclose(m_library);
#endif
        m_library = nullptr;
    }
}

std::vector<GpuDeviceInfo> OpenCLRuntime::GetGpuDevices() {
    std::vector<GpuDeviceInfo> devices;

    if (!m_available) {
        return devices;
    }

    // Get platforms
    cl_uint numPlatforms = 0;
    if ((intptr_t)clGetPlatformIDs(0, nullptr, &numPlatforms) != CL_SUCCESS || numPlatforms == 0) {
        return devices;
    }

    std::vector<cl_platform_id> platforms(numPlatforms);
    clGetPlatformIDs(numPlatforms, platforms.data(), nullptr);

    // Enumerate devices on each platform
    for (cl_uint p = 0; p < numPlatforms; ++p) {
        cl_uint numDevices = 0;
        if ((intptr_t)clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 0, nullptr, &numDevices) != CL_SUCCESS) {
            continue;
        }

        if (numDevices == 0) continue;

        std::vector<cl_device_id> devIds(numDevices);
        clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, numDevices, devIds.data(), nullptr);

        for (cl_uint d = 0; d < numDevices; ++d) {
            GpuDeviceInfo info;
            info.platformId = p;
            info.deviceId = d;

            char buffer[256];
            size_t retSize;

            if (clGetDeviceInfo &&
                (intptr_t)clGetDeviceInfo(devIds[d], CL_DEVICE_NAME, sizeof(buffer), buffer, &retSize) == CL_SUCCESS) {
                info.name = std::string(buffer, retSize > 0 ? retSize - 1 : 0);
            }

            if (clGetDeviceInfo &&
                (intptr_t)clGetDeviceInfo(devIds[d], CL_DEVICE_VENDOR, sizeof(buffer), buffer, &retSize) == CL_SUCCESS) {
                info.vendor = std::string(buffer, retSize > 0 ? retSize - 1 : 0);
            }

            cl_uint computeUnits = 0;
            if (clGetDeviceInfo &&
                (intptr_t)clGetDeviceInfo(devIds[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(computeUnits), &computeUnits, nullptr) == CL_SUCCESS) {
                info.computeUnits = computeUnits;
            }

            size_t maxWorkGroup = 0;
            if (clGetDeviceInfo &&
                (intptr_t)clGetDeviceInfo(devIds[d], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxWorkGroup), &maxWorkGroup, nullptr) == CL_SUCCESS) {
                info.maxWorkGroupSize = maxWorkGroup;
            }

            cl_ulong globalMem = 0;
            if (clGetDeviceInfo &&
                (intptr_t)clGetDeviceInfo(devIds[d], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(globalMem), &globalMem, nullptr) == CL_SUCCESS) {
                info.globalMemorySize = globalMem;
            }

            devices.push_back(info);
            LogPrintf("OpenCL: Found GPU: %s (%s) - %u CUs, %lu MB\n",
                     info.name.c_str(), info.vendor.c_str(),
                     info.computeUnits, info.globalMemorySize / (1024 * 1024));
        }
    }

    return devices;
}

bool OpenCLRuntime::Initialize(int platformId, int deviceId) {
    if (!m_available) {
        return false;
    }

    // Get platform
    cl_uint numPlatforms = 0;
    clGetPlatformIDs(0, nullptr, &numPlatforms);
    if (platformId >= (int)numPlatforms) {
        LogPrintf("OpenCL: Invalid platform ID %d\n", platformId);
        return false;
    }

    std::vector<cl_platform_id> platforms(numPlatforms);
    clGetPlatformIDs(numPlatforms, platforms.data(), nullptr);

    // Get device
    cl_uint numDevices = 0;
    clGetDeviceIDs(platforms[platformId], CL_DEVICE_TYPE_GPU, 0, nullptr, &numDevices);
    if (deviceId >= (int)numDevices) {
        LogPrintf("OpenCL: Invalid device ID %d\n", deviceId);
        return false;
    }

    std::vector<cl_device_id> devIds(numDevices);
    clGetDeviceIDs(platforms[platformId], CL_DEVICE_TYPE_GPU, numDevices, devIds.data(), nullptr);
    m_device = devIds[deviceId];

    // Create context with explicit platform properties (required by some NVIDIA drivers)
    cl_int err = CL_SUCCESS;
    cl_context_properties properties[] = {
        CL_CONTEXT_PLATFORM, (cl_context_properties)platforms[platformId],
        0
    };
    m_context = clCreateContext(properties, 1, &m_device, nullptr, nullptr, &err);
    if (err != CL_SUCCESS || !m_context) {
        LogPrintf("OpenCL: Failed to create context (err=%d)\n", err);
        return false;
    }

    // Create command queue
    m_queue = clCreateCommandQueue(m_context, m_device, 0, &err);
    if (err != CL_SUCCESS || !m_queue) {
        LogPrintf("OpenCL: Failed to create command queue (err=%d)\n", err);
        clReleaseContext(m_context);
        m_context = nullptr;
        return false;
    }

    // Get device info
    auto devices = GetGpuDevices();
    for (const auto& dev : devices) {
        if (dev.platformId == platformId && dev.deviceId == deviceId) {
            m_currentDevice = dev;
            break;
        }
    }

    m_initialized = true;
    LogPrintf("OpenCL: Initialized on %s\n", m_currentDevice.name.c_str());
    return true;
}

void OpenCLRuntime::Cleanup() {
    if (m_queue) {
        clReleaseCommandQueue(m_queue);
        m_queue = nullptr;
    }
    if (m_context) {
        clReleaseContext(m_context);
        m_context = nullptr;
    }
    m_initialized = false;
}

} // namespace opencl
