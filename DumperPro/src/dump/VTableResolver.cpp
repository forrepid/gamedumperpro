// ============================================================================
// DumperPro - dynamic vtable function resolver
//
// Fully dynamic slot discovery: fingerprints are matched against every slot's
// function body (from the local module image copy) - no hardcoded indices.
// Handles MSVC thunk / adjustor stubs and votes across several vftables.
// ============================================================================
#include "dump/VTableResolver.h"
#include "ue/UEObject.h"
#include "ue/ObjectArray.h"
#include "core/MemoryReader.h"
#include "core/Pattern.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

namespace dumper {

namespace {

constexpr u32 kMaxSlots = 512;      // slots scanned per vtable
constexpr u32 kMaxThunkDepth = 8;   // adjustor-chain limit
constexpr int kMinConfidence = 1;   // votes required

std::vector<std::vector<PatByte>> ParseFingerprints(const std::vector<std::string>& patterns) {
    std::vector<std::vector<PatByte>> out;
    for (const std::string& p : patterns) {
        std::vector<PatByte> pat = Pattern::Parse(p);
        if (pat.empty()) {
            Log::Debug("VTableResolver: invalid fingerprint skipped: %s", p.c_str());
            continue;
        }
        out.push_back(std::move(pat));
    }
    return out;
}

// anchored match: pattern must match at offset 0 of the function bytes
bool MatchAtStart(const u8* bytes, size_t size, const std::vector<PatByte>& pat) {
    if (!bytes || pat.empty() || pat.size() > size) return false;
    for (size_t i = 0; i < pat.size(); i++) {
        if ((bytes[i] & pat[i].mask) != (pat[i].value & pat[i].mask)) return false;
    }
    return true;
}

struct SlotHit {
    int slot = -1;
    u64 slotFuncVA = 0;   // raw vtable entry
    u64 finalVA = 0;      // post-thunk target
    int depth = 0;
    int fingerprint = -1;
};

struct VTVote {
    int votes = 0;
    int firstSlot = -1;
    u64 firstSlotFuncVA = 0;
    int depth = 0;
    bool inPrimary = false;
};

} // namespace

// ---------------------------------------------------------------------------
// built-in fingerprints (extendable via games.ini fingerprint.<Name>)
// ---------------------------------------------------------------------------

std::vector<std::string> VTableResolver::BuiltinFingerprints(const std::string& funcName) {
    std::string n = str::Lower(funcName);
    if (n == "processevent") {
        return {
            // classic MSVC prologue: spill to stack, reserve locals
            "4C 8B DC 49 89 5B ?? 49 89 6B ?? 49 89 73 ?? 57 41 56 41 57 48 81 EC ?? ?? ?? ??",
            "4C 8B DC 49 89 5B ?? 49 89 6B ?? 49 89 73 ?? 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ??",
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 81 EC ?? ?? ?? ?? 49 8B F9",
        };
    }
    if (n == "postrender") {
        return {
            "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30 48 8B F9 48 8B DA 48 8B 49",
        };
    }
    if (n == "processremotefunction") {
        return {
            "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ??",
        };
    }
    return {};
}

// ---------------------------------------------------------------------------
// vtable discovery
// ---------------------------------------------------------------------------

static bool IsMetaClassName(const std::string& n) {
    return n == "Class" || n == "ScriptStruct" || n == "Enum" || n == "Function" ||
           n == "Package" || n == "Object";
}

u64 VTableResolver::FindVTableOfObjectClass() {
    if (!ctx_.objects || !ctx_.objects->IsReady()) return 0;
    const i32 n = ctx_.objects->Num();
    const i32 cap = std::min<i32>(n, 2000);
    for (i32 i = 0; i < cap; i++) {
        u64 obj = ctx_.objects->ObjectAt(i);
        if (!obj) continue;
        UEObject o(&ctx_, obj, i);
        std::string cls = o.GetClassName();
        if (cls.empty() || IsMetaClassName(cls)) continue;
        u64 vft = ctx_.reader->ReadPtrOr(obj);
        if (vft && ctx_.mod && ctx_.mod->Contains(vft)) return vft;
    }
    return 0;
}

u64 VTableResolver::FindVTableOfClass(const std::string& className) {
    if (!ctx_.objects || !ctx_.objects->IsReady()) return 0;
    const i32 n = ctx_.objects->Num();
    const std::string want = str::Lower(className);
    for (i32 i = 0; i < n; i++) {
        u64 obj = ctx_.objects->ObjectAt(i);
        if (!obj) continue;
        UEObject o(&ctx_, obj, i);
        std::string cls = o.GetClassName();
        if (cls.empty() || !str::Contains(str::Lower(cls), want)) continue;
        u64 vft = ctx_.reader->ReadPtrOr(obj);
        if (vft && ctx_.mod && ctx_.mod->Contains(vft)) return vft;
    }
    return 0;
}

std::vector<u64> VTableResolver::CollectVTables(int max) {
    std::vector<u64> out;
    if (!ctx_.objects || !ctx_.objects->IsReady()) return out;
    const i32 n = ctx_.objects->Num();
    for (i32 i = 0; i < n && (int)out.size() < max; i++) {
        u64 obj = ctx_.objects->ObjectAt(i);
        if (!obj) continue;
        u64 vft = ctx_.reader->ReadPtrOr(obj);
        if (!vft || !ctx_.mod || !ctx_.mod->Contains(vft)) continue;
        if (std::find(out.begin(), out.end(), vft) == out.end()) out.push_back(vft);
    }
    return out;
}

// ---------------------------------------------------------------------------
// thunk / adjustor unwinding
// ---------------------------------------------------------------------------

u64 VTableResolver::UnwindThunks(u64 funcVA, int& depth, bool* hitImport) {
    if (hitImport) *hitImport = false;
    u64 cur = funcVA;
    ModuleImage* mod = ctx_.mod;
    if (!mod) return cur;

    for (int d = 0; d < (int)kMaxThunkDepth; d++) {
        const u8* b = mod->VaPtr(cur);
        if (!b || !mod->InExecSection(cur)) break;

        // JMP rel32
        if (b[0] == 0xE9) {
            u64 target = PatternScanner::RipTargetVA(mod->Base, 0, b, 32, 1, 5);
            if (!mod->Contains(target) || !mod->InExecSection(target)) {
                if (hitImport) *hitImport = true;
                break;
            }
            cur = target;
            depth = d + 1;
            continue;
        }
        // JMP rel8
        if (b[0] == 0xEB) {
            i8 rel = (i8)b[1];
            u64 target = cur + 2 + (u64)(i64)rel;
            if (!mod->Contains(target) || !mod->InExecSection(target)) {
                if (hitImport) *hitImport = true;
                break;
            }
            cur = target;
            depth = d + 1;
            continue;
        }
        // JMP [RIP+rel32] -> import stub, stop here
        if (b[0] == 0xFF && b[1] == 0x25) {
            if (hitImport) *hitImport = true;
            break;
        }
        // SUB/ADD RCX, imm8 + JMP (single-inheritance adjustor)
        if (b[0] == 0x48 && b[1] == 0x83 && (b[2] == 0xE9 || b[2] == 0xC1)) {
            if (b[3] == 0xE9) {
                u64 target = PatternScanner::RipTargetVA(mod->Base, 3, b, 64, 1, 5);
                if (mod->Contains(target) && mod->InExecSection(target)) {
                    cur = target;
                    depth = d + 1;
                    continue;
                }
            } else if (b[3] == 0xEB) {
                i8 rel = (i8)b[4];
                u64 target = cur + 4 + 2 + (u64)(i64)rel;
                if (mod->Contains(target) && mod->InExecSection(target)) {
                    cur = target;
                    depth = d + 1;
                    continue;
                }
            }
            break;
        }
        // SUB/ADD RCX, imm32 + JMP (large adjustor)
        if (b[0] == 0x48 && b[1] == 0x81 && (b[2] == 0xE9 || b[2] == 0xC1)) {
            if (b[7] == 0xE9) {
                u64 target = PatternScanner::RipTargetVA(mod->Base, 7, b, 64, 1, 5);
                if (mod->Contains(target) && mod->InExecSection(target)) {
                    cur = target;
                    depth = d + 1;
                    continue;
                }
            } else if (b[7] == 0xEB) {
                i8 rel = (i8)b[8];
                u64 target = cur + 7 + 2 + (u64)(i64)rel;
                if (mod->Contains(target) && mod->InExecSection(target)) {
                    cur = target;
                    depth = d + 1;
                    continue;
                }
            }
            break;
        }
        break; // real function body
    }
    return cur;
}

// ---------------------------------------------------------------------------
// vtable scanning
// ---------------------------------------------------------------------------

VTResult VTableResolver::ScanVTable(u64 vftVA, const std::vector<std::vector<PatByte>>& fps, int minIndex) {
    VTResult res;
    ModuleImage* mod = ctx_.mod;
    IMemoryReader* r = ctx_.reader;
    if (!mod || !r) return res;

    u64 slots[kMaxSlots] = {};
    const u32 readable = std::min<u32>(kMaxSlots, (u32)((mod->Base + mod->SizeOfImage() - vftVA) / 8));
    if (readable == 0) return res;
    if (!r->Read(vftVA, slots, readable * sizeof(u64))) {
        // fall back to per-slot reads
        for (u32 i = 0; i < readable; i++) {
            if (!r->ReadPtr(vftVA + (u64)i * 8ull, slots[i])) slots[i] = 0;
        }
    }

    std::map<u64, VTVote> votes;
    for (u32 s = 0; s < readable; s++) {
        if ((int)s < minIndex) continue;
        u64 funcVA = slots[s];
        if (!funcVA || !mod->Contains(funcVA) || !mod->InExecSection(funcVA)) continue;
        const u8* body = mod->VaPtr(funcVA);
        if (!body) continue;

        for (size_t f = 0; f < fps.size(); f++) {
            if (!MatchAtStart(body, 96, fps[f])) continue;

            int depth = 0;
            bool import = false;
            u64 finalVA = UnwindThunks(funcVA, depth, &import);
            if (!mod->Contains(finalVA) || !mod->InExecSection(finalVA)) continue;

            VTVote& v = votes[finalVA];
            v.votes++;
            if (v.firstSlot < 0) {
                v.firstSlot = (int)s;
                v.firstSlotFuncVA = funcVA;
                v.depth = depth;
            }
            Log::Debug("VTableResolver: slot %u -> func %s (final %s, depth %d, fp %zu)",
                       s, Hex(funcVA).c_str(), Hex(finalVA).c_str(), depth, f);
            break; // one fingerprint per slot is enough
        }
    }

    if (votes.empty()) return res;

    // winner: most votes; tie -> lowest slot
    u64 winner = 0;
    for (const auto& kv : votes) {
        if (!winner || kv.second.votes > votes[winner].votes ||
            (kv.second.votes == votes[winner].votes && kv.second.firstSlot < votes[winner].firstSlot)) {
            winner = kv.first;
        }
    }
    const VTVote& w = votes[winner];
    res.found = true;
    res.slot = w.firstSlot;
    res.funcVA = winner;
    res.rva = mod->VaToRva(winner);
    res.slotRVA = mod->VaToRva(vftVA + (u64)w.firstSlot * 8ull);
    res.via = "heuristic";
    res.thunkDepth = w.depth;
    res.votes = w.votes;
    return res;
}

VTResult VTableResolver::ResolveByFingerprints(const std::string& funcName, u64 vtableVA, int minIndex) {
    VTResult out;
    if (!vtableVA) {
        out.note = std::string(funcName) + ": vtable not located";
        return out;
    }
    std::vector<std::vector<PatByte>> fps = ParseFingerprints(BuiltinFingerprints(funcName));
    if (fps.empty()) {
        out.note = funcName + ": no valid fingerprints available";
        return out;
    }

    // primary vtable first, then confirmation votes across several distinct vftables
    VTResult primary = ScanVTable(vtableVA, fps, minIndex);

    std::map<u64, int> votes;
    std::map<u64, VTResult> byVA;
    if (primary.found) {
        votes[primary.funcVA] += primary.votes;
        byVA[primary.funcVA] = primary;
        Log::Debug("VTableResolver: primary vtable %s -> %s (slot %d)",
                   Hex(vtableVA).c_str(), Hex(primary.funcVA).c_str(), primary.slot);
    }

    for (u64 vft : CollectVTables(6)) {
        if (vft == vtableVA) continue;
        VTResult r = ScanVTable(vft, fps, minIndex);
        if (r.found) {
            votes[r.funcVA] += r.votes;
            if (!byVA.count(r.funcVA)) byVA[r.funcVA] = r;
        }
    }

    if (votes.empty()) {
        out.note = funcName + ": no fingerprint match in vtable; extend fingerprint." +
                   str::Lower(funcName) + " in games.ini";
        return out;
    }

    // post-thunk voting: converge on the most-voted final RVA
    u64 winner = 0;
    for (const auto& kv : votes) {
        if (!winner || kv.second > votes[winner]) winner = kv.first;
    }
    out = byVA[winner];
    out.votes = votes[winner];
    out.found = true;
    return out;
}

VTResult VTableResolver::ResolveProcessEvent() {
    u64 vft = FindVTableOfObjectClass();
    VTResult res = ResolveByFingerprints("ProcessEvent", vft, minIndexSlot);
    if (!res.found && res.note.empty()) res.note = "ProcessEvent: not found";
    return res;
}

VTResult VTableResolver::ResolvePostRender() {
    u64 vft = FindVTableOfClass("GameViewportClient");
    VTResult res = ResolveByFingerprints("PostRender", vft, minIndexSlot);
    if (!res.found && res.note.empty()) res.note = "PostRender: GameViewportClient instance not found";
    return res;
}

VTResult VTableResolver::ResolveProcessRemoteFunction() {
    u64 vft = FindVTableOfClass("NetDriver");
    VTResult res = ResolveByFingerprints("ProcessRemoteFunction", vft, minIndexSlot);
    if (!res.found && res.note.empty()) res.note = "ProcessRemoteFunction: NetDriver instance not found";
    return res;
}

} // namespace dumper
