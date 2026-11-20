// ============================================================================
//  UnrealDumperX - driver.cpp - user-mode half of the kernel bridge.
// ============================================================================
#include "driver.h"

namespace udx {

static constexpr DWORD kIoctlRead = 0x222000;   // matches driver/udxdrv.c
static constexpr DWORD kIoctlBase = 0x222004;

bool Driver::connect(const char* devicePath) {
    if (connected()) return true;
    handle_ = CreateFileA(devicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return connected();
}

bool Driver::loadService(const std::wstring& sysPath) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, L"UnrealDumperX", SERVICE_ALL_ACCESS);
    if (!svc) {
        svc = CreateServiceW(scm, L"UnrealDumperX", L"UnrealDumperX",
                             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             sysPath.c_str(), nullptr, nullptr, nullptr,
                             nullptr, nullptr);
        if (!svc) { CloseServiceHandle(scm); return false; }
    }
    SERVICE_STATUS st{};
    QueryServiceStatus(svc, &st);
    if (st.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(svc, 0, nullptr)) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool Driver::unloadService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, L"UnrealDumperX", SERVICE_ALL_ACCESS);
    bool ok = false;
    if (svc) {
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
        ok = true;
    }
    CloseServiceHandle(scm);
    return ok;
}

bool Driver::connectOrLoad(const std::wstring& sysPath) {
    if (connect()) return true;
    if (!sysPath.empty() && loadService(sysPath)) return connect();
    return false;
}

void Driver::disconnect() {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
    handle_ = nullptr;
}

bool Driver::readMem(u64 pid, u64 src, void* dst, u32 size) {
    if (!connected()) return false;
    UdxReadReq req{pid, src, (u64)(uintptr_t)dst, size, 0};
    DWORD ret = 0;
    if (!DeviceIoControl(handle_, kIoctlRead, &req, sizeof(req), &req,
                         sizeof(req), &ret, nullptr))
        return false;
    return req.status == 1;
}

bool Driver::baseInfo(u64 pid, u64* imageBase, u32* imageSize) {
    if (!connected()) return false;
    UdxBaseReq req{pid, 0, 0, 0};
    DWORD ret = 0;
    if (!DeviceIoControl(handle_, kIoctlBase, &req, sizeof(req), &req,
                         sizeof(req), &ret, nullptr))
        return false;
    if (req.status != 1) return false;
    if (imageBase) *imageBase = req.imageBase;
    if (imageSize) *imageSize = req.imageSize;
    return true;
}

} // namespace udx
