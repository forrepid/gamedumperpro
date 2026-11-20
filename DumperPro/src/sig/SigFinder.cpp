// ============================================================================
// DumperPro - auto sig-finder with hit validation + heuristic struct scans
//
// Flow per global (GNames first, GObjects second):
//   1. explicit address from profile / games.ini   (validated)
//   2. config pattern from games.ini               (scanned + validated)
//   3. built-in signature candidates               (scanned + validated)
//   4. heuristic struct scan over data sections    (validated)
// Every candidate must pass structural validation before it is accepted.
// ============================================================================
#include "sig/SigFinder.h"
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"
#include "ue/UEVersion.h"
#include "core/Pattern.h"
#include "core/MemoryReader.h"
#include "config/Config.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

namespace dumper {

namespace {

bool ValidateGNames(IMemoryReader& r, UEOffsets& off, const UEVersion& v, u64 va, i32 nameCount, std::string* why) {
    (void)nameCount;
    return NameArray::ValidateCandidate(r, off, v, va, why);
}

bool ValidateGObjects(IMemoryReader& r, UEOffsets& off, const UEVersion& v, u64 va, i32 nameCount, std::string* why) {
    return ObjectArray::ValidateCandidate(r, off, v, va, nameCount, why);
}

bool PlausibleHeapPtr(u64 p, u64 notEqual = 0) {
    return p != 0 && (p & 7ull) == 0 && p >= 0x10000ull && p < 0x7FFFFFFEFFFFull && p != notEqual;
}

} // namespace

// ---------------------------------------------------------------------------
// built-in candidate signatures
// ---------------------------------------------------------------------------

const std::vector<SigFinder::SigCand>& SigFinder::GObjectsSigs() {
    static const std::vector<SigCand> sigs = {
        {"48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8",            3,  7,  "UE4.25+/UE5: mov rax,[GObjects]; lea rdx,[rsp+x]; call"},
        {"48 8B 05 ?? ?? ?? ?? 48 89 44 24 ?? E8",            3,  7,  "UE5 alt: mov rax,[GObjects]; mov [rsp+x],rax; call"},
        {"48 8B 05 ?? ?? ?? ?? EB 13 48 8B 0D",               3,  7,  "UE5 variant: mov rax,[GObjects]; jmp; mov rcx,[..]"},
        {"4C 8B 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8D 54 24", 3, 11, "UE5: mov r12,[..]; mov rax,[GObjects]; lea rdx"},
        {"89 5C 24 ?? 89 44 24 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 0D", 10, 14, "UE4: save regs; mov rax,[GObjects]; mov rcx,[..]"},
        {"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8D 05",      3,  7,  "UE4: mov rax,[GObjects]; test rax,rax; jz; lea"},
    };
    return sigs;
}

const std::vector<SigFinder::SigCand>& SigFinder::GNamesSigs() {
    static const std::vector<SigCand> sigs = {
        {"48 8D 35 ?? ?? ?? ?? EB 16",                        3,  7,  "UE5 FNamePool: lea rsi,[pool]; jmp"},
        {"48 8D 3D ?? ?? ?? ?? EB 13",                        3,  7,  "UE5/UE4 FNamePool: lea rdi,[pool]; jmp"},
        {"48 8D 05 ?? ?? ?? ?? EB 13 48 8D 0D",               3,  7,  "UE4.23+ FNamePool: lea rax,[pool]; jmp; lea rcx"},
        {"74 09 48 8D 15 ?? ?? ?? ?? EB 16",                  5,  9,  "UE4 FNamePool: jz; lea rdx,[pool]; jmp"},
        {"48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01", 3, 7, "UE4 FNamePool: lea rcx,[pool]; call"},
    };
    return sigs;
}

// ---------------------------------------------------------------------------
// construction
// ---------------------------------------------------------------------------

SigFinder::SigFinder(IMemoryReader& r, ModuleImage& img, UEOffsets& off, const UEVersion& v,
                     const NameArray* names, Config& cfg)
    : r_(r), img_(img), off_(off), ver_(v), names_(names), cfg_(cfg) {}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

SigHit SigFinder::MakeHit(size_t hitOffset, int dispPos, int instLen, const std::string& pat, const char* via) {
    SigHit h;
    h.hitOffset = hitOffset;
    h.va = PatternScanner::RipTargetVA(img_.Base, hitOffset, img_.Data.data(), img_.Data.size(), dispPos, instLen);
    h.pattern = pat;
    std::vector<PatByte> parsed = Pattern::Parse(pat);
    h.extended = PatternScanner::BuildExtendedSig(img_.Data.data(), img_.Data.size(), hitOffset,
                                                  parsed.size(), dispPos, instLen, 8, 8);
    h.via = via;
    return h;
}

u64 SigFinder::TryPatternList(const std::vector<SigCand>& list,
                              bool (*validate)(IMemoryReader&, UEOffsets&, const UEVersion&, u64, i32, std::string*),
                              bool usesNames, const char* what, SigHit& hit, std::string* via) {
    (void)usesNames;
    const i32 nameCount = names_ ? names_->Num() : 0;

    for (const SigCand& c : list) {
        std::vector<PatByte> pat = Pattern::Parse(c.pat);
        if (pat.empty()) {
            Log::Debug("SigFinder[%s]: invalid built-in pattern skipped", what);
            continue;
        }
        std::vector<size_t> hits = PatternScanner::FindAll(img_.Data.data(), img_.Data.size(), pat, 64);
        Log::Debug("SigFinder[%s]: pattern '%s' -> %llu hits (%s)", what, c.pat,
                   (unsigned long long)hits.size(), c.note);
        for (size_t off : hits) {
            u64 candVA = PatternScanner::RipTargetVA(img_.Base, off, img_.Data.data(), img_.Data.size(),
                                                     c.dispPos, c.instLen);
            if (!candVA) continue;
            std::string why;
            if (validate(r_, off_, ver_, candVA, nameCount, &why)) {
                Log::Debug("SigFinder[%s]: VALID @ RVA 0x%llX -> VA %s", what,
                           (unsigned long long)off, Hex(candVA).c_str());
                hit = MakeHit(off, c.dispPos, c.instLen, c.pat, "sig");
                if (via) *via = "sig (" + std::string(c.note) + ")";
                return candVA;
            }
            Log::Debug("SigFinder[%s]: hit @ RVA 0x%llX -> VA %s rejected: %s", what,
                       (unsigned long long)off, Hex(candVA).c_str(), why.c_str());
        }
    }
    return 0;
}

u64 SigFinder::TryConfigPattern(const std::string& key,
                                bool (*validate)(IMemoryReader&, UEOffsets&, const UEVersion&, u64, i32, std::string*),
                                bool usesNames, const char* what, SigHit& hit, std::string* via) {
    (void)usesNames;
    const i32 nameCount = names_ ? names_->Num() : 0;
    std::vector<std::string> patterns = cfg_.KeyPatterns("", key);
    for (const std::string& p : patterns) {
        std::vector<PatByte> pat = Pattern::Parse(p);
        if (pat.empty()) {
            Log::Warn("SigFinder[%s]: invalid config pattern '%s'", what, p.c_str());
            continue;
        }
        std::vector<size_t> hits = PatternScanner::FindAll(img_.Data.data(), img_.Data.size(), pat, 64);
        for (size_t off : hits) {
            // config patterns are assumed to be "RIP-relative load" style: disp32 at +3, inst len 7
            u64 candVA = PatternScanner::RipTargetVA(img_.Base, off, img_.Data.data(), img_.Data.size(), 3, 7);
            if (!candVA) continue;
            std::string why;
            if (validate(r_, off_, ver_, candVA, nameCount, &why)) {
                Log::Ok("SigFinder[%s]: config pattern matched @ VA %s", what, Hex(candVA).c_str());
                hit = MakeHit(off, 3, 7, p, "config pattern");
                if (via) *via = "config pattern";
                return candVA;
            }
            Log::Debug("SigFinder[%s]: config pattern hit rejected: %s", what, why.c_str());
        }
    }
    return 0;
}

u64 SigFinder::FromConfigAddress(const std::string& key,
                                 bool (*validate)(IMemoryReader&, UEOffsets&, const UEVersion&, u64, i32, std::string*),
                                 const char* what, SigHit& hit, std::string* via) {
    const i32 nameCount = names_ ? names_->Num() : 0;
    u64 va = cfg_.KeyU64("", key, 0);
    if (!va) return 0;
    std::string why;
    if (validate(r_, off_, ver_, va, nameCount, &why)) {
        SigHit h;
        h.va = va;
        h.via = "config";
        hit = h;
        if (via) *via = "config";
        Log::Ok("SigFinder[%s]: explicit address from games.ini validated @ %s", what, Hex(va).c_str());
        return va;
    }
    Log::Warn("SigFinder[%s]: games.ini address %s failed validation: %s", what, Hex(va).c_str(), why.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// heuristic struct scans (no signatures needed)
// ---------------------------------------------------------------------------

namespace {

struct DataRange {
    u32 rva = 0;
    u32 size = 0;
};

std::vector<DataRange> DataSectionRanges(const ModuleImage& img) {
    std::vector<DataRange> out;
    if (!img.pe || !img.pe->Valid()) return out;
    for (const PESection& s : img.pe->Sections()) {
        if (s.exec) continue;                 // data-ish only
        u32 size = std::max(s.vs, s.rawSize);
        size = std::min<u32>(size, img.SizeOfImage() - std::min(s.va, img.SizeOfImage()));
        if (size >= 0x1000) out.push_back({s.va, size});
    }
    return out;
}

} // namespace

u64 SigFinder::HeuristicScan_GNames(SigHit& hit, std::string* via) {
    std::vector<DataRange> ranges = DataSectionRanges(img_);
    u64 scanned = 0;
    constexpr u64 kMaxQwords = 8'000'000;

    for (const DataRange& dr : ranges) {
        const u32 end = dr.rva + dr.size - 8;
        for (u32 rva = dr.rva; rva + 0x28 < end && scanned < kMaxQwords; rva += 8, scanned++) {
            const u8* p = img_.RvaPtr(rva);
            if (!p) break;
            u32 cB = 0, cC = 0;
            memcpy(&cB, p + 8, 4);
            memcpy(&cC, p + 0xC, 4);
            if (cB < 1 || cB > 0x4000) continue;
            if (cC == 0 || cC >= 0x20000) continue;

            u64 block0 = 0;
            memcpy(&block0, p + 0x10, 8);
            if (!PlausibleHeapPtr(block0)) continue;

            u64 candVA = img_.RvaToVa(rva);
            std::string why;
            if (NameArray::ValidateCandidate(r_, off_, ver_, candVA, &why)) {
                SigHit h;
                h.va = candVA;
                h.via = "heuristic struct scan";
                hit = h;
                if (via) *via = "heuristic struct scan";
                Log::Debug("SigFinder[GNames]: heuristic hit @ RVA 0x%X", rva);
                return candVA;
            }
        }
        if (scanned >= kMaxQwords) break;
    }
    return 0;
}

u64 SigFinder::HeuristicScan_GObjects(SigHit& hit, std::string* via) {
    std::vector<DataRange> ranges = DataSectionRanges(img_);
    const i32 nameCount = names_ ? names_->Num() : 0;
    u64 scanned = 0;
    constexpr u64 kMaxQwords = 8'000'000;
    u64 candidatesTried = 0;

    for (const DataRange& dr : ranges) {
        const u32 end = dr.rva + dr.size - 8;
        for (u32 rva = dr.rva; rva + 0x28 < end && scanned < kMaxQwords; rva += 8, scanned++) {
            const u8* p = img_.RvaPtr(rva);
            if (!p) break;

            // counts at variant A: numE@+0x1C, maxE@+0x18, numC@+0x24, maxC@+0x20
            u32 numE = 0, maxE = 0, numC = 0, maxC = 0;
            memcpy(&numE, p + 0x1C, 4);
            memcpy(&maxE, p + 0x18, 4);
            memcpy(&numC, p + 0x24, 4);
            memcpy(&maxC, p + 0x20, 4);

            if (numE < 1000 || numE > 30'000'000) continue;
            if (maxE < numE || maxE > 40'000'000) continue;
            if (numC < 1 || numC > 4096 || maxC < numC) continue;

            bool consistent = false;
            for (u32 cs : {10240u, 65536u, 16384u, 32768u, 131072u}) {
                if (((u64)numE + cs - 1) / cs == numC && ((u64)maxE + cs - 1) / cs == maxC) {
                    consistent = true;
                    break;
                }
            }
            if (!consistent) continue;

            u64 tablePtr = 0;
            memcpy(&tablePtr, p + 0x10, 8);
            if (!PlausibleHeapPtr(tablePtr)) continue;

            if (++candidatesTried > 64) break;
            u64 candVA = img_.RvaToVa(rva);
            std::string why;
            if (ObjectArray::ValidateCandidate(r_, off_, ver_, candVA, nameCount, &why)) {
                SigHit h;
                h.va = candVA;
                h.via = "heuristic struct scan";
                hit = h;
                if (via) *via = "heuristic struct scan";
                Log::Debug("SigFinder[GObjects]: heuristic hit @ RVA 0x%X", rva);
                return candVA;
            }
            Log::Debug("SigFinder[GObjects]: candidate @ RVA 0x%X rejected: %s", rva, why.c_str());
        }
        if (scanned >= kMaxQwords || candidatesTried > 64) break;
    }
    return 0;
}

u64 SigFinder::HeuristicScan_GWorld(SigHit& hit, std::string* via) {
    if (!names_ || names_->Num() <= 0) return 0;

    std::vector<DataRange> ranges = DataSectionRanges(img_);
    u64 scanned = 0;
    constexpr u64 kMaxQwords = 4'000'000;
    std::vector<u64> found;

    for (const DataRange& dr : ranges) {
        const u32 end = dr.rva + dr.size - 8;
        for (u32 rva = dr.rva; rva < end && scanned < kMaxQwords; rva += 8, scanned++) {
            const u8* p = img_.RvaPtr(rva);
            if (!p) break;
            u64 cand = 0;
            memcpy(&cand, p, 8);
            if (!PlausibleHeapPtr(cand)) continue;

            // object class name must be "World"
            u64 cls = 0;
            if (!r_.ReadPtr(cand + off_.objClassOff, cls)) continue;
            if (!PlausibleHeapPtr(cls)) continue;
            i32 nameIdx = 0;
            if (!r_.ReadI32(cls + off_.objNameOff, nameIdx)) continue;
            if (nameIdx < 0 || nameIdx >= names_->Num()) continue;
            if (names_->Get(nameIdx) != "World") continue;

            // the world object itself must have a valid name
            i32 objNameIdx = 0;
            if (!r_.ReadI32(cand + off_.objNameOff, objNameIdx)) continue;
            if (objNameIdx < 0 || objNameIdx >= names_->Num()) continue;

            found.push_back(cand);
            if (found.size() >= 4) break;
        }
        if (found.size() >= 4 || scanned >= kMaxQwords) break;
    }

    if (found.empty()) return 0;
    if (found.size() >= 4) {
        Log::Warn("GWorld heuristic ambiguous (%llu candidates)", (unsigned long long)found.size());
        return 0;
    }

    SigHit h;
    h.va = found[0];
    h.via = "heuristic struct scan";
    hit = h;
    if (via) *via = "heuristic struct scan";
    return found[0];
}

// ---------------------------------------------------------------------------
// finders
// ---------------------------------------------------------------------------

u64 SigFinder::FindGNames(std::string* via) {
    // Resolve, then feed the candidate VA into off_.GNamesVA so that
    // NameArray::TryInit (which reads off.GNamesVA) can parse it. Without
    // this wiring a freshly discovered sig/heuristic candidate is returned
    // but the parser still sees "unresolved" (real-world UE5.1 shipping
    // binary regression caught in 1b, 2026-11-20).
    u64 va = FindGNamesImpl(via);
    if (va && off_.GNamesVA != va) {
        off_.GNamesVA = va;
        Log::Debug("SigFinder[GNames]: candidate VA wired to off.GNamesVA (%s)", Hex(va).c_str());
    }
    return va;
}

u64 SigFinder::FindGNamesImpl(std::string* via) {
    const auto validate = &ValidateGNames;

    // 1. profile-provided address (games.ini [Game] gnames=... already applied to off_)
    if (off_.GNamesVA) {
        std::string why;
        if (ValidateGNames(r_, off_, ver_, off_.GNamesVA, 0, &why)) {
            SigHit h;
            h.va = off_.GNamesVA;
            h.via = "profile";
            GNamesHit = h;
            if (via) *via = "profile";
            return off_.GNamesVA;
        }
        Log::Warn("GNames profile address failed validation: %s - continuing with scan", why.c_str());
    }
    // 2. explicit [Global]/[Sig] gnames=...
    u64 va = FromConfigAddress("gnames", validate, "GNames", GNamesHit, via);
    if (va) return va;
    // 3. config patterns
    va = TryConfigPattern("gnames_pattern", validate, false, "GNames", GNamesHit, via);
    if (va) return va;
    // 4. built-in sigs
    va = TryPatternList(GNamesSigs(), validate, false, "GNames", GNamesHit, via);
    if (va) return va;
    // 5. heuristic struct scan
    va = HeuristicScan_GNames(GNamesHit, via);
    if (va) return va;

    Log::Err("GNames: no valid candidate (sigs + struct scan failed)");
    return 0;
}

u64 SigFinder::FindGObjects(std::string* via) {
    // Same wiring as FindGNames: ObjectArray::TryInit reads off.GObjectsVA.
    u64 va = FindGObjectsImpl(via);
    if (va && off_.GObjectsVA != va) {
        off_.GObjectsVA = va;
        Log::Debug("SigFinder[GObjects]: candidate VA wired to off.GObjectsVA (%s)", Hex(va).c_str());
    }
    return va;
}

u64 SigFinder::FindGObjectsImpl(std::string* via) {
    const auto validate = &ValidateGObjects;

    // 1. profile-provided address
    if (off_.GObjectsVA) {
        const i32 nameCount = names_ ? names_->Num() : 0;
        std::string why;
        if (ValidateGObjects(r_, off_, ver_, off_.GObjectsVA, nameCount, &why)) {
            SigHit h;
            h.va = off_.GObjectsVA;
            h.via = "profile";
            GObjectsHit = h;
            if (via) *via = "profile";
            return off_.GObjectsVA;
        }
        Log::Warn("GObjects profile address failed validation: %s - continuing with scan", why.c_str());
    }
    // 2. explicit [Global]/[Sig] gobjects=...
    u64 va = FromConfigAddress("gobjects", validate, "GObjects", GObjectsHit, via);
    if (va) return va;
    // 3. config patterns
    va = TryConfigPattern("gobjects_pattern", validate, true, "GObjects", GObjectsHit, via);
    if (va) return va;
    // 4. built-in sigs
    va = TryPatternList(GObjectsSigs(), validate, true, "GObjects", GObjectsHit, via);
    if (va) return va;
    // 5. heuristic struct scan
    va = HeuristicScan_GObjects(GObjectsHit, via);
    if (va) return va;

    Log::Err("GObjects: no valid candidate (sigs + struct scan failed)");
    return 0;
}

u64 SigFinder::FindGWorld(std::string* via) {
    u64 va = HeuristicScan_GWorld(GWorldHit, via);
    if (va) Log::Debug("SigFinder[GWorld]: heuristic hit @ %s", Hex(va).c_str());
    return va;
}

} // namespace dumper
