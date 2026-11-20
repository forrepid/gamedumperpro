// ============================================================================
//  UnrealDumperX - driver.h
//  Module 8 - Kernel Driver Support.
//
//  The user-mode side talks to an optional kernel driver through
//  DeviceIoControl. The driver's reference implementation lives in
//  driver/udxdrv.c and implements exactly this IOCTL contract:
//
//    IOCTL_UDX_READ   (0x222000)  struct UdxReadReq
//                                   { u64 pid; u64 src; u64 dst; u32 size;
//                                     u32 status; }
//                                 -> reads `size` bytes from target `pid`
//                                    address `src` into driver buffer, copies
//                                    them back to the caller, sets status=1.
//    IOCTL_UDX_BASE   (0x222004)  struct UdxBaseReq
//                                   { u64 pid; u64 imageBase; u32 imageSize;
//                                     u32 status; }
//                                 -> image base/size of the target's main exe.
//
//  Why a driver? Large scans (full committed-range walks for GSpots-style
//  anchoring) are dramatically more stable across anti-cheat-protected
//  pages: reads that OpenProcess/ReadProcessMemory reject silently succeed
//  through PsLookupProcessByProcessId + KeStackAttachProcess.
//
//  Usage: UnrealDumperX.exe --driver            (try to connect)
//                          --driver-load C:\udx\UnrealDumperX.sys
//  Loading requires an elevated shell, a test-signed driver and
//  `bcdedit /set testsigning on`.
// ============================================================================
#pragma once
#include "common.h"

namespace udx {

struct UdxReadReq {
    u64 pid;
    u64 src;
    u64 dst;
    u32 size;
    u32 status;
};

struct UdxBaseReq {
    u64 pid;
    u64 imageBase;
    u32 imageSize;
    u32 status;
};

class Driver {
public:
    bool connect(const char* devicePath = "\\\\.\\UnrealDumperX");
    bool connectOrLoad(const std::wstring& sysPath);
    void disconnect();

    bool connected() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    // Kernel-assisted memory read (struct-copy semantics, METHOD_BUFFERED).
    bool readMem(u64 pid, u64 src, void* dst, u32 size);
    // Main image base/size of the target (used to sanity-check modules).
    bool baseInfo(u64 pid, u64* imageBase, u32* imageSize);

    // Loads the .sys through the SCM service manager (admin + testsigning).
    static bool loadService(const std::wstring& sysPath);
    static bool unloadService();

private:
    HANDLE handle_ = nullptr;
};

} // namespace udx
