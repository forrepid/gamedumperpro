// ============================================================================
//  UnrealDumperX - finder.cpp
// ============================================================================
#include "finder.h"
#include "ini.h"
#include "log.h"

namespace udx::ue {

namespace {

// Rip-relative candidate: sig with the disp32 wildcarded at `dispOffset`.
struct RipCandidate {
    const char* sig;
    int dispOffset;
    int instrLen;
};

// Known candidate patterns (best-effort starting points; STRICT verification
// decides - users can pin their own pairs in games.ini at any time).
static const RipCandidate kGObjectsPatterns[] = {
    {"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 ?? 48 85 C0", 3, 7},
    {"48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 EB 09 48 8B 0C D1", 3, 7},
    {"48 8B 05 ?? ?? ?? ?? 48 63 C9 48 85 C0 74 ?? 48 8B 04 CA", 3, 7},
    {"48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01", 3, 7},
    {"48 89 1D ?? ?? ?? ?? EB ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0", 8, 12},
};

static const RipCandidate kGNamesPatterns[] = {
    {"74 09 48 8D 15 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8", 5, 9},
    {"48 8D 15 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8", 3, 7},
    {"48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8", 3, 7},
    {"89 5C 24 ?? 89 44 24 ?? 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D", 10, 14},
};

static const RipCandidate kGWorldPatterns[] = {
    {"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 ?? 48 85 C9 74 ?? 48 8B 51", 3, 7},
    {"48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 48 8B 43 ?? 48 85 C0 74 ?? 48 85 DB", 3, 7},
};

bool vtInModule(const std::vector<ModuleInfo>& mods, u64 v) {
    for (const auto& m : mods)
        if (m.contains(v) && m.contains(v + 8)) return true;
    return false;
}

bool saneObject(Process& proc, const std::vector<ModuleInfo>& mods, u64 obj) {
    if (!obj || !proc.ptrReadable(obj)) return false;
    return vtInModule(mods, proc.read<u64>(obj));
}

// ---------------------------------------------------------------------------
// GObjects verification: probes the TUObjectArray sub-struct at several
// offsets, validates counters + chunks + first items, and fills `off`.
// ---------------------------------------------------------------------------
bool verifyGObjects(Process& proc, Offsets& off, uintptr_t cand,
                    const char* source) {
    const auto mods = proc.modules();
    for (int tuOff : {0x00, 0x10, 0x20}) {
        const uintptr_t base = cand + tuOff;

        // ---- chunked layout: [chunkPtrArray][Max][Num][MaxChunks][NumChunks]
        {
            const u64 chunkArr = proc.read<u64>(base);
            const i32 maxE = proc.read<i32>(base + 4);
            const i32 numE = proc.read<i32>(base + 8);
            const i32 maxC = proc.read<i32>(base + 12);
            const i32 numC = proc.read<i32>(base + 16);

            const bool countersOk = numE > 0 && numE < 50 * 1000 * 1000 &&
                                    maxE >= numE && numC > 0 && numC <= 256 &&
                                    maxC >= numC;
            if (countersOk && chunkArr && proc.ptrReadable(chunkArr)) {
                bool chunksOk = true;
                usize saneItems = 0, probes = 0;
                for (i32 c = 0; c < std::min<i32>(numC, 4); ++c) {
                    const u64 chunk = proc.read<u64>(chunkArr + (u64)c * 8);
                    if (!chunk || !proc.ptrReadable(chunk)) { chunksOk = false; break; }
                }
                if (chunksOk) {
                    const i32 cap = maxC > 0 ? maxE / numC : 0x10000;
                    for (i32 i = 0; i < 16 && i < numE; ++i) {
                        const u64 chunk = proc.read<u64>(chunkArr + (u64)(i / std::max(cap, 1)) * 8);
                        const u64 obj = proc.read<u64>(chunk + (u64)(i % std::max(cap, 1)) * 0x18);
                        ++probes;
                        if (saneObject(proc, mods, obj)) ++saneItems;
                    }
                    if ((float)saneItems / (float)std::max<usize>(probes, 1) >= 0.5f) {
                        off.gObjects = cand;
                        off.tuObjectArrayOffset = tuOff;
                        off.chunkedArray = true;
                        off.objectItemSize = 0x18;
                        off.chunkCapacity = std::max(cap, 0x10000);
                        off.record("TuObjectArrayOffset", tuOff, source, 1.0f);
                        off.record("ObjectItemSize", 0x18, source, 1.0f);
                        off.record("ChunkCapacity", off.chunkCapacity, source, 1.0f);
                        return true;
                    }
                }
            }
        }
        // ---- legacy linear layout: [itemsPtr][Max][Num]
        {
            const u64 items = proc.read<u64>(base);
            const i32 numE = proc.read<i32>(base + 8);
            const i32 maxE = proc.read<i32>(base + 4);
            const bool ok = numE > 0 && numE < 50 * 1000 * 1000 && maxE >= numE &&
                            items && proc.ptrReadable(items);
            if (ok) {
                usize saneItems = 0;
                for (i32 i = 0; i < 16 && i < numE; ++i) {
                    const u64 obj = proc.read<u64>(items + (u64)i * 0x18);
                    if (saneObject(proc, mods, obj)) ++saneItems;
                }
                if (saneItems >= 4) {
                    off.gObjects = cand;
                    off.tuObjectArrayOffset = tuOff;
                    off.chunkedArray = false;
                    off.objectItemSize = 0x18;
                    off.chunkCapacity = numE;
                    off.record("TuObjectArrayOffset", tuOff, source, 1.0f);
                    off.record("ObjectItemSize", 0x18, source, 1.0f);
                    off.record("ChunkCapacity", numE, source, 1.0f);
                    return true;
                }
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// GNames verification (FNamePool) and TNameEntryArray verification
// ---------------------------------------------------------------------------
bool verifyGNamesPool(Process& proc, Offsets& off, uintptr_t cand,
                      const char* source) {
    static const int kBlocksOff[] = {0x10, 0x08, 0x00, 0x18, 0x20};
    static const int kStrides[] = {2, 4};
    static const int kShifts[] = {6, 1};

    for (int blocksOff : kBlocksOff) {
        const u64 block0 = proc.read<u64>(cand + blocksOff);
        if (!block0 || !proc.ptrReadable(block0)) continue;
        for (int stride : kStrides) {
            for (int shift : kShifts) {
                std::string n0, n1;
                if (!decodeEntryAt(proc, block0, 2, shift, n0)) continue;
                if (n0 != "None") continue;
                if (!decodeEntryAt(proc, block0 + (usize)stride, 2, shift, n1)) continue;
                if (n1 != "ByteProperty") continue;
                off.gNames = cand;
                off.nameBlocksOffset = blocksOff;
                off.nameStride = stride;
                off.nameLenShift = shift;
                off.nameHeaderSize = 2;
                off.nameChunkBits = 16;
                off.record("NameBlocksOffset", blocksOff, source, 1.0f);
                off.record("NameStride", stride, source, 1.0f);
                off.record("NameLenShift", shift, source, 1.0f);
                return true;
            }
        }
    }
    return false;
}

bool verifyGNamesIndirect(Process& proc, Offsets& off, uintptr_t cand,
                          const char* source) {
    const u64 chunk0 = proc.read<u64>(cand);
    if (!chunk0 || !proc.ptrReadable(chunk0)) return false;
    const u64 entry0 = proc.read<u64>(chunk0);
    if (!entry0) return false;
    for (int hdrSize : {4, 2}) {
        std::string n0, n1;
        if (!decodeEntryAt(proc, entry0, hdrSize, 6, n0)) continue;
        if (n0 != "None") continue;
        const u64 entry1 = proc.read<u64>(chunk0 + 8);
        if (!entry1 || !decodeEntryAt(proc, entry1, hdrSize, 6, n1)) continue;
        if (n1 != "ByteProperty") continue;
        off.gNames = cand;
        off.nameHeaderSize = hdrSize;
        off.nameLenShift = 6;
        off.nameChunkBits = 14;
        off.nameStride = 0;
        off.record("NameHeaderSize", hdrSize, source, 1.0f);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Rip-relative candidate scanning helper
// ---------------------------------------------------------------------------
std::vector<u64> resolveRipCandidates(Process& proc, const RipCandidate& rc) {
    std::vector<u64> out;
    const Pattern pat = parseIda(rc.sig);
    if (pat.empty()) return out;
    if (pat.length() < (usize)rc.dispOffset + 4) return out;

    const ModuleInfo* main = proc.mainModule();
    std::vector<ModuleInfo> mods;
    if (main) mods.push_back(*main);
    for (const auto& m : proc.modules()) {
        if (mods.size() >= 4) break;
        if (main && m.base == main->base) continue;
        mods.push_back(m);
    }
    for (const auto& m : mods) {
        for (const u64 hit : scanModuleAll(proc, m, pat, 32)) {
            const i32 disp = proc.read<i32>(hit + rc.dispOffset);
            const u64 global = hit + (u64)rc.instrLen + (u64)(i64)disp;
            out.push_back(global);
        }
    }
    return out;
}

template <typename VerifyFn>
bool tryRipPatterns(Process& proc, const RipCandidate* cands, usize count,
                    VerifyFn verify, std::string* methodOut) {
    for (usize i = 0; i < count; ++i) {
        for (const u64 global : resolveRipCandidates(proc, cands[i])) {
            if (verify(global)) {
                if (methodOut) *methodOut = fmt("known pattern #%zu", i + 1);
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// GObjects anchor scan (GSpots-style structural search in .data/.bss)
// ---------------------------------------------------------------------------
bool findGObjectsByAnchor(Process& proc, Offsets& off) {
    const ModuleInfo* main = proc.mainModule();
    if (!main) return false;
    for (const auto& sec : peSectionsOf(proc, *main)) {
        const std::string n = lower(sec.name);
        if (n.find(".data") == std::string::npos && n != ".bss") continue;
        if (sec.size == 0 || sec.size > 128ull * 1024 * 1024) continue;
        std::vector<u8> buf(sec.size, 0);
        if (!proc.read(sec.start, buf.data(), buf.size())) continue;

        for (usize i = 0; i + 24 <= buf.size(); i += 4) {
            const u64 chunkArr = *(u64*)(buf.data() + i);
            const i32 maxE = *(i32*)(buf.data() + i + 8);
            const i32 numE = *(i32*)(buf.data() + i + 12);
            const i32 maxC = *(i32*)(buf.data() + i + 16);
            const i32 numC = *(i32*)(buf.data() + i + 20);
            if (numE < 1000 || numE > 50 * 1000 * 1000) continue;
            if (maxE < numE || numC <= 0 || numC > 256 || maxC < numC) continue;
            if (!chunkArr || (chunkArr & 7)) continue;
            if (!proc.ptrReadable(chunkArr)) continue;
            if (verifyGObjects(proc, off, sec.start + i, "anchor")) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// GNames anchor scan: find the block holding "None", then walk back to the
// Blocks[] array inside FNamePool (both live in the module data sections).
// ---------------------------------------------------------------------------
bool findGNamesByAnchor(Process& proc, Offsets& off) {
    const ModuleInfo* main = proc.mainModule();
    if (!main) return false;

    static const int kShifts[] = {6, 1};
    static const int kBlocksOff[] = {0x10, 0x08, 0x00, 0x18, 0x20};
    static const int kStrides[] = {2, 4};

    for (const auto& sec : peSectionsOf(proc, *main)) {
        const std::string n = lower(sec.name);
        if (n.find(".data") == std::string::npos && n != ".bss") continue;
        if (sec.size == 0 || sec.size > 128ull * 1024 * 1024) continue;
        std::vector<u8> buf(sec.size, 0);
        if (!proc.read(sec.start, buf.data(), buf.size())) continue;

        // 1) locate the "None" entry block pointer (FNamePool Blocks[0]).
        for (usize i = 0; i + 8 <= buf.size(); i += 8) {
            const u64 block0 = *(u64*)(buf.data() + i);
            if (!block0 || (block0 & 7)) continue;
            if (!proc.ptrReadable(block0)) continue;
            bool noneOk = false;
            int shiftHit = -1;
            for (int shift : kShifts) {
                std::string n0;
                if (decodeEntryAt(proc, block0, 2, shift, n0) && n0 == "None") {
                    noneOk = true;
                    shiftHit = shift;
                    break;
                }
            }
            if (!noneOk) continue;

            // 2) find the qword slot in this section that stores `block0`
            //    (that slot is Blocks[0]; the pool base is P - blocksOffset).
            for (usize j = 0; j + 8 <= buf.size(); j += 8) {
                if (*(u64*)(buf.data() + j) != block0) continue;
                for (int blocksOff : kBlocksOff) {
                    const uintptr_t pool = sec.start + j - (usize)blocksOff;
                    if (pool == 0 || pool < main->base) continue;
                    for (int stride : kStrides) {
                        std::string n1;
                        const u64 b0 = proc.read<u64>(pool + blocksOff);
                        if (b0 != block0) continue;
                        if (decodeEntryAt(proc, block0 + (usize)stride, 2,
                                          shiftHit, n1) && n1 == "ByteProperty") {
                            off.gNames = pool;
                            off.nameBlocksOffset = blocksOff;
                            off.nameStride = stride;
                            off.nameLenShift = shiftHit;
                            off.nameHeaderSize = 2;
                            off.nameChunkBits = 16;
                            off.record("NameBlocksOffset", blocksOff, "anchor", 1.0f);
                            off.record("NameStride", stride, "anchor", 1.0f);
                            off.record("NameLenShift", shiftHit, "anchor", 1.0f);
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// Core address resolution pipeline
// ---------------------------------------------------------------------------
FinderResult findCoreAddresses(Process& proc, Offsets& off, const Ini& ini,
                               UEVersion ver, std::vector<SigRecord>& sigs) {
    FinderResult res;
    off.applyIni(ini);   // authoritative addresses first (NOTE #6)

    // ---- GObjects ------------------------------------------------------------
    const ModuleInfo* main = proc.mainModule();
    if (off.gObjects) {
        res.gObjects = verifyGObjects(proc, off, off.gObjects, "ini");
        res.methodObjects = "games.ini (authoritative)";
    }
    if (!res.gObjects) {
        res.gObjects = tryRipPatterns(
            proc, kGObjectsPatterns, (sizeof(kGObjectsPatterns) / sizeof(kGObjectsPatterns[0])),
            [&](u64 g) { return verifyGObjects(proc, off, g, "known"); },
            &res.methodObjects);
        if (res.gObjects) {
            SigRecord r;
            r.name = "GObjects";
            r.source = "known";
            r.resolved = off.gObjects;
            if (main) {
                r.module = main->name;
                for (const auto& rc : kGObjectsPatterns) {
                    const Pattern pat = parseIda(rc.sig);
                    for (const u64 global : resolveRipCandidates(proc, rc)) {
                        if (global == off.gObjects ||
                            global == off.gObjects - off.tuObjectArrayOffset) {
                            r.mainSig = patternToString(pat);
                            r.extSig = buildExtendedSignature(proc, *main, global,
                                                              pat.length());
                            r.resolved = global;
                            break;
                        }
                    }
                    if (!r.mainSig.empty()) break;
                }
            }
            sigs.push_back(std::move(r));
        }
    }
    if (!res.gObjects) {
        res.gObjects = findGObjectsByAnchor(proc, off);
        res.methodObjects = "data-section anchor scan";
        if (res.gObjects && main) {
            SigRecord r;
            r.name = "GObjects";
            r.source = "anchor";
            r.resolved = off.gObjects;
            r.module = main->name;
            sigs.push_back(std::move(r));
        }
    }
    if (res.gObjects)
        log::ok(fmt("GObjects @ %s (%s)", toHex(off.gObjects).c_str(),
                    res.methodObjects.c_str()));
    else
        log::error("GObjects bulunamadi");

    // ---- GNames --------------------------------------------------------------
    if (off.gNames) {
        res.gNames = verifyGNamesPool(proc, off, off.gNames, "ini") ||
                     verifyGNamesIndirect(proc, off, off.gNames, "ini");
        res.methodNames = "games.ini (authoritative)";
    }
    if (!res.gNames) {
        res.gNames = tryRipPatterns(
            proc, kGNamesPatterns, (sizeof(kGNamesPatterns) / sizeof(kGNamesPatterns[0])),
            [&](u64 g) {
                return verifyGNamesPool(proc, off, g, "known") ||
                       verifyGNamesIndirect(proc, off, g, "known");
            },
            &res.methodNames);
    }
    if (!res.gNames) {
        res.gNames = findGNamesByAnchor(proc, off);
        res.methodNames = "None-entry anchor scan";
    }
    res.gNames ? log::ok(fmt("GNames @ %s (%s)", toHex(off.gNames).c_str(),
                             res.methodNames.c_str()))
               : log::error("GNames bulunamadi");

    return res;
}

// ---------------------------------------------------------------------------
// GWorld (needs the name pool for class-name validation)
// ---------------------------------------------------------------------------
bool findGWorld(Process& proc, Offsets& off, UEVersion ver,
                const NameDb& names, std::vector<SigRecord>& sigs) {
    const ModuleInfo* main = proc.mainModule();
    if (off.gWorld) {
        const u64 w = proc.read<u64>(off.gWorld);
        if (w && proc.ptrReadable(w)) return true;
        off.gWorld = 0;
    }
    if (!main) return false;

    for (const auto& rc : kGWorldPatterns) {
        for (const u64 varAddr : resolveRipCandidates(proc, rc)) {
            const u64 world = proc.read<u64>(varAddr);
            if (!world || !proc.ptrReadable(world)) continue;
            // Validate: object -> class -> FName == "World".
            const u64 cls = proc.read<u64>(world + off.uobjClass);
            if (cls && proc.ptrReadable(cls)) {
                const u32 nameIdx = proc.read<u32>(cls + off.uobjName);
                const std::string clsName = names.get(nameIdx);
                if (!clsName.empty() && lower(clsName) != "world") continue;
            }
            off.gWorld = world;
            SigRecord r;
            r.name = "GWorld";
            r.source = "known";
            const Pattern pat = parseIda(rc.sig);
            r.mainSig = patternToString(pat);
            r.extSig = buildExtendedSignature(proc, *main, varAddr, pat.length());
            r.resolved = varAddr;
            r.module = main->name;
            sigs.push_back(std::move(r));
            log::ok(fmt("GWorld @ %s", toHex(world).c_str()));
            return true;
        }
    }
    log::warn("GWorld bulunamadi (opsiyonel)");
    return false;
}

// ---------------------------------------------------------------------------
// ObjectDb
// ---------------------------------------------------------------------------
bool ObjectDb::init(Process& proc, Offsets& off) {
    proc_ = &proc;
    off_ = &off;
    if (!off.gObjects) return false;
    const uintptr_t base = off.gObjects + off.tuObjectArrayOffset;
    num_ = proc.read<i32>(base + off.objNumElements);
    if (num_ < 0 || num_ > 50 * 1000 * 1000) { num_ = 0; return false; }
    chunked_ = off.chunkedArray;
    // Cross-check a few items before trusting the array.
    usize sane = 0;
    const auto mods = proc.modules();
    for (i32 i = 0; i < std::min<i32>(num_, 16); ++i)
        if (saneObject(proc, mods, objectAt(i))) ++sane;
    if (sane < 4 && num_ > 16) {
        log::warn("ObjectDb: ilk 16 nesneden cogu gecersiz - dizi sekilli sapkabilir");
    }
    return num_ > 0;
}

u64 ObjectDb::objectAt(i32 idx) const {
    if (!proc_ || !off_ || idx < 0 || idx >= num_) return 0;
    const uintptr_t base = off_->gObjects + off_->tuObjectArrayOffset;
    if (chunked_) {
        const u64 chunkArr = proc_->read<u64>(base);
        if (!chunkArr) return 0;
        const i32 chunkIdx = idx / off_->chunkCapacity;
        const u64 chunk = proc_->read<u64>(chunkArr + (u64)chunkIdx * 8);
        if (!chunk) return 0;
        return proc_->read<u64>(chunk + (u64)(idx % off_->chunkCapacity) *
                                          (u64)off_->objectItemSize);
    }
    const u64 items = proc_->read<u64>(base);
    if (!items) return 0;
    return proc_->read<u64>(items + (u64)idx * (u64)off_->objectItemSize);
}

std::vector<u64> ObjectDb::sample(i32 max) const {
    std::vector<u64> out;
    const i32 n = std::min<i32>(num_, max);
    out.reserve(n);
    for (i32 i = 0; i < n; ++i) {
        const u64 o = objectAt(i);
        if (o) out.push_back(o);
    }
    return out;
}

} // namespace udx::ue
