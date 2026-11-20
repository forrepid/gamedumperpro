// DumperPro - dynamic vtable function resolver (ProcessEvent / PostRender / ProcessRemoteFunction)
#pragma once
#include "../framework.h"
#include "core/Pattern.h"

namespace dumper {

class UEContext;

struct VTResult {
    bool found = false;
    int slot = -1;            // vtable index
    u64 funcVA = 0;           // final (post-thunk) function VA
    u64 rva = 0;              // RVA within the main module
    u64 slotRVA = 0;          // RVA of the vtable slot entry
    std::string via;          // "vtable>heuristic" | "vtable>pattern"
    int thunkDepth = 0;
    int votes = 0;
    std::string note;
};

class VTableResolver {
public:
    explicit VTableResolver(UEContext& ctx) : ctx_(ctx) {}

    int minIndexSlot = 8;    // slots 0..1 are MSVC destructors; reject suspiciously low indices

    VTResult ResolveProcessEvent();          // UObject::ProcessEvent (UObject vtable)
    VTResult ResolvePostRender();            // UGameViewportClient::PostRender
    VTResult ResolveProcessRemoteFunction(); // UNetDriver::ProcessRemoteFunction

    // generic entry: resolve funcName using fingerprint list against a class' vtable
    VTResult ResolveByFingerprints(const std::string& funcName, u64 vtableVA, int minIndex);

    static std::vector<std::string> BuiltinFingerprints(const std::string& funcName);

private:
    UEContext& ctx_;

    u64 FindVTableOfObjectClass();                    // vft of any plain UObject instance
    u64 FindVTableOfClass(const std::string& className);
    std::vector<u64> CollectVTables(int max = 6);     // several distinct vftables for voting

    VTResult ScanVTable(u64 vftVA, const std::vector<std::vector<PatByte>>& fps, int minIndex);
    u64 UnwindThunks(u64 funcVA, int& depth, bool* hitImport = nullptr);
};

} // namespace dumper
