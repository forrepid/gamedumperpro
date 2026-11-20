// ============================================================================
//  UnrealDumperX - offsets.cpp
//  Module 7 - Runtime Offset Discovery.
//
//  IMPORTANT NOTE #5: every field is accepted only when its per-field
//  confidence reaches kConfidenceThreshold (65%).
//  IMPORTANT NOTE #7: voting samples at most kMaxProbeObjects (400) live
//  objects - fast on any game, small or huge.
//  IMPORTANT NOTE #6: games.ini values are authoritative and are never
//  overwritten by probing; saveMissingToIni only ADDS missing keys.
// ============================================================================
#include "ue_types.h"
#include "ini.h"
#include "fname.h"
#include "log.h"

namespace udx::ue {

// ---------------------------------------------------------------------------
// Provenance bookkeeping
// ---------------------------------------------------------------------------
void Offsets::record(const std::string& key, int value, const std::string& source,
                     float confidence) {
    meta[key] = {value, confidence, source};
}

const OffsetEntry& Offsets::metaFor(const std::string& key) const {
    static const OffsetEntry empty;
    auto it = meta.find(key);
    return it == meta.end() ? empty : it->second;
}

// ---------------------------------------------------------------------------
// Defaults per engine generation
// ---------------------------------------------------------------------------
void Offsets::applyDefaultsFor(UEVersion v) {
    if (isUE5(v)) {
        // UE5 FNamePool: 2-byte header with lowercase probe hash (>>6), 2-byte
        // stride, 64KB blocks (IMPORTANT NOTE #1).
        nameStride = 2;
        nameLenShift = 6;
        nameHeaderSize = 2;
        nameChunkBits = 16;
        // IMPORTANT NOTE #2: UE5 stores FName::Number AFTER the index.
        fNameNumberDelta = 0x04;
    } else if (usesFNamePool(v)) {           // 4.23 - 4.27
        nameStride = 4;
        nameLenShift = 1;                      // header { bIsWide:1 | Len:15 }
        nameHeaderSize = 2;
        nameChunkBits = 16;
        // IMPORTANT NOTE #2: UE4 builds commonly keep Number BEFORE the index.
        fNameNumberDelta = -0x04;
    } else if (usesIndirectArray(v)) {       // 4.20 - 4.22 TNameEntryArray
        nameHeaderSize = 4;
        nameLenShift = 6;
        nameChunkBits = 14;                    // 16384 entries per chunk
        nameStride = 0;                        // indirect pointer table
        fNameNumberDelta = -0x04;
    }
    record("NameStride", nameStride, "default", 0);
    record("NameLenShift", nameLenShift, "default", 0);
    record("FNameNumberDelta", fNameNumberDelta, "default", 0);
}

// ---------------------------------------------------------------------------
// games.ini authority (IMPORTANT NOTE #6)
// ---------------------------------------------------------------------------
void Offsets::applyIni(const Ini& ini) {
    auto pin = [&](const char* key, int& field) {
        if (ini.has("Offsets", key)) {
            field = ini.getI32("Offsets", key, field);
            record(key, field, "ini", 1.0f);
        }
    };
    if (ini.has("Addresses", "GObjects")) gObjects = ini.getU64("Addresses", "GObjects", 0);
    if (ini.has("Addresses", "GNames"))   gNames   = ini.getU64("Addresses", "GNames", 0);
    if (ini.has("Addresses", "GWorld"))   gWorld   = ini.getU64("Addresses", "GWorld", 0);

    pin("TuObjectArrayOffset", tuObjectArrayOffset);
    pin("ObjMaxElements", objMaxElements);
    pin("ObjNumElements", objNumElements);
    pin("ObjMaxChunks", objMaxChunks);
    pin("ObjNumChunks", objNumChunks);
    pin("ObjectItemSize", objectItemSize);
    pin("ChunkCapacity", chunkCapacity);
    pin("UObject_Flags", uobjFlags);
    pin("UObject_Index", uobjIndex);
    pin("UObject_Class", uobjClass);
    pin("UObject_Name", uobjName);
    pin("UObject_Outer", uobjOuter);
    pin("FNameNumberDelta", fNameNumberDelta);
    pin("NameBlocksOffset", nameBlocksOffset);
    pin("NameStride", nameStride);
    pin("NameLenShift", nameLenShift);
    pin("NameHeaderSize", nameHeaderSize);
    pin("NameChunkBits", nameChunkBits);
    if (ini.has("Offsets", "ChunkedArray")) chunkedArray = ini.getBool("Offsets", "ChunkedArray", chunkedArray);
}

void Offsets::saveMissingToIni(Ini& ini) const {
    auto add = [&](const char* key, int value) {
        if (!ini.has("Offsets", key)) ini.setI32("Offsets", key, value);
    };
    if (gObjects && !ini.has("Addresses", "GObjects")) ini.setU64("Addresses", "GObjects", gObjects);
    if (gNames && !ini.has("Addresses", "GNames"))     ini.setU64("Addresses", "GNames", gNames);
    if (gWorld && !ini.has("Addresses", "GWorld"))     ini.setU64("Addresses", "GWorld", gWorld);
    add("TuObjectArrayOffset", tuObjectArrayOffset);
    add("ObjNumElements", objNumElements);
    add("ObjectItemSize", objectItemSize);
    add("ChunkCapacity", chunkCapacity);
    add("UObject_Flags", uobjFlags);
    add("UObject_Index", uobjIndex);
    add("UObject_Class", uobjClass);
    add("UObject_Name", uobjName);
    add("UObject_Outer", uobjOuter);
    add("FNameNumberDelta", fNameNumberDelta);
    add("NameBlocksOffset", nameBlocksOffset);
    add("NameStride", nameStride);
    add("NameLenShift", nameLenShift);
    add("NameHeaderSize", nameHeaderSize);
    add("NameChunkBits", nameChunkBits);
}

std::string Offsets::describe() const {
    std::string out;
    auto line = [&](const char* name, int value, const std::string& key) {
        char buf[160];
        const OffsetEntry& m = metaFor(key);
        snprintf(buf, sizeof(buf), "%-24s 0x%-04X conf %.2f  [%s]\n",
                 name, (unsigned)value, m.confidence, m.source.c_str());
        out += buf;
    };
    out += "GObjects          = " + toHex(gObjects) + "\n";
    out += "GNames            = " + toHex(gNames) + "\n";
    out += "GWorld            = " + toHex(gWorld) + "\n";
    line("UObject.Flags", uobjFlags, "UObject_Flags");
    line("UObject.Index", uobjIndex, "UObject_Index");
    line("UObject.Class", uobjClass, "UObject_Class");
    line("UObject.Name", uobjName, "UObject_Name");
    line("UObject.Outer", uobjOuter, "UObject_Outer");
    line("FNameNumberDelta", fNameNumberDelta, "FNameNumberDelta");
    line("ObjectItemSize", objectItemSize, "ObjectItemSize");
    line("NameBlocksOffset", nameBlocksOffset, "NameBlocksOffset");
    line("NameStride", nameStride, "NameStride");
    line("NameLenShift", nameLenShift, "NameLenShift");
    return out;
}

// ---------------------------------------------------------------------------
// Discovery helpers
// ---------------------------------------------------------------------------
namespace {

struct ModRange { uintptr_t start, end; };

std::vector<ModRange> collectModRanges(Process& proc) {
    std::vector<ModRange> out;
    for (const auto& m : proc.modules())
        out.push_back({m.base, m.base + m.size});
    return out;
}

bool inMods(const std::vector<ModRange>& mods, u64 v) {
    for (const auto& r : mods)
        if (v >= r.start && v < r.end) return true;
    return false;
}

bool isSaneObjectPtr(Process& proc, const std::vector<ModRange>& mods, u64 obj) {
    if (!obj || !proc.ptrReadable(obj)) return false;
    const u64 vft = proc.read<u64>(obj);
    return vft && inMods(mods, vft);
}

// FUObjectItem object fetch using the current layout assumptions.
u64 itemObject(Process& proc, const Offsets& off, i32 idx) {
    const uintptr_t base = off.gObjects + off.tuObjectArrayOffset;
    if (off.chunkedArray) {
        const uintptr_t chunkArr = proc.read<u64>(base);
        if (!chunkArr) return 0;
        const i32 chunkIdx = idx / off.chunkCapacity;
        const uintptr_t chunk = proc.read<u64>(chunkArr + (u64)chunkIdx * 8);
        if (!chunk) return 0;
        return proc.read<u64>(chunk + (u64)(idx % off.chunkCapacity) * off.objectItemSize);
    }
    const uintptr_t items = proc.read<u64>(base);
    if (!items) return 0;
    return proc.read<u64>(items + (u64)idx * off.objectItemSize);
}

// Generic voting helpers end here; individual field votes are inlined below
// so each one can report its own candidate scores.

} // namespace

// ---------------------------------------------------------------------------
// IMPORTANT NOTE #2: FName::Number placement probe (+0x04 vs -0x04).
// ---------------------------------------------------------------------------
void probeFNameNumberDelta(Process& proc, Offsets& off, const NameDb& names,
                           const std::vector<u64>& objects) {
    struct Cand { int delta; float score; };
    Cand cands[] = {{0x04, 0.0f}, {-0x04, 0.0f}};
    for (auto& c : cands) {
        usize good = 0;
        for (const u64 obj : objects) {
            const i32 num = proc.read<i32>(obj + off.uobjName + c.delta);
            if (num >= 0 && num < 100000) ++good;
        }
        c.score = objects.empty() ? 0.0f : (float)good / (float)objects.size();
    }
    const Cand* best = (cands[0].score >= cands[1].score) ? &cands[0] : &cands[1];
    off.fNameNumberDelta = best->delta;
    off.record("FNameNumberDelta", best->delta,
               fmt("vote(%.2f)", best->score), best->score);
}

// ---------------------------------------------------------------------------
// Main discovery entry
// ---------------------------------------------------------------------------
bool discoverRuntimeOffsets(Process& proc, Offsets& off, const Ini& ini,
                            UEVersion ver, const NameDb& names) {
    if (!off.gObjects) return false;
    off.applyDefaultsFor(ver);
    off.applyIni(ini);   // authoritative pass (NOTE #6)

    const auto mods = collectModRanges(proc);

    // ---- sample up to 400 live objects (IMPORTANT NOTE #7) ------------------
    std::vector<u64> objects;
    std::vector<i32> indices;
    {
        i32 num = proc.read<i32>(off.gObjects + off.tuObjectArrayOffset +
                                 off.objNumElements);
        if (num <= 0 || num > 50 * 1000 * 1000) num = kMaxProbeObjects;
        const i32 limit = std::min<i32>(num, kMaxProbeObjects);
        objects.reserve(limit);
        indices.reserve(limit);
        for (i32 i = 0; i < limit; ++i) {
            const u64 obj = itemObject(proc, off, i);
            if (obj && isSaneObjectPtr(proc, mods, obj)) {
                objects.push_back(obj);
                indices.push_back(i);
            }
        }
        log::info(fmt("Offset discovery sample: %zu canli nesne (limit %d)",
                      objects.size(), kMaxProbeObjects));
    }
    if (objects.size() < 16) {
        log::warn("Yeterli canli nesne yok - varsayilan offsetlerle devam ediliyor");
        return false;
    }

    // ---- UObject.Class ------------------------------------------------------
    if (!ini.has("Offsets", "UObject_Class")) {
        struct C { int off; float score; };
        C cands[] = {{0x10, 0}, {0x18, 0}, {0x28, 0}};
        for (auto& c : cands) {
            usize good = 0;
            for (const u64 obj : objects) {
                const u64 cls = proc.read<u64>(obj + c.off);
                if (cls && isSaneObjectPtr(proc, mods, cls)) ++good;
            }
            c.score = (float)good / objects.size();
        }
        C* best = &cands[0];
        for (auto& c : cands) if (c.score > best->score) best = &c;
        if (best->score >= kConfidenceThreshold) {
            off.uobjClass = best->off;
            off.record("UObject_Class", best->off,
                       fmt("vote(%.2f)", best->score), best->score);
        } else {
            off.record("UObject_Class", off.uobjClass, "default", best->score);
            log::warn(fmt("UObject.Class guven esigi asilmadi (%.2f < %.2f)",
                          best->score, kConfidenceThreshold));
        }
    }

    // ---- UObject.Name (validated through the FName pool) ---------------------
    if (!ini.has("Offsets", "UObject_Name")) {
        struct C { int off; float score; };
        C cands[] = {{0x18, 0}, {0x20, 0}, {0x28, 0}};
        for (auto& c : cands) {
            if (c.off == off.uobjClass) { c.score = -1.0f; continue; }
            usize good = 0;
            for (const u64 obj : objects) {
                const u32 idx = proc.read<u32>(obj + c.off);
                if (!names.get(idx).empty()) ++good;
            }
            c.score = (float)good / objects.size();
        }
        C* best = &cands[0];
        for (auto& c : cands) if (c.score > best->score) best = &c;
        if (best->score >= kConfidenceThreshold && best->off != off.uobjClass) {
            off.uobjName = best->off;
            off.record("UObject_Name", best->off,
                       fmt("vote(%.2f)", best->score), best->score);
        } else {
            off.record("UObject_Name", off.uobjName, "default", std::max(0.f, best->score));
        }
    }

    // ---- UObject.Outer -------------------------------------------------------
    if (!ini.has("Offsets", "UObject_Outer")) {
        struct C { int off; float score; };
        C cands[] = {{0x20, 0}, {0x28, 0}, {0x30, 0}};
        for (auto& c : cands) {
            if (c.off == off.uobjClass || c.off == off.uobjName) { c.score = -1.0f; continue; }
            usize good = 0;
            for (const u64 obj : objects) {
                const u64 outer = proc.read<u64>(obj + c.off);
                if (outer == 0 || isSaneObjectPtr(proc, mods, outer)) ++good;
            }
            c.score = (float)good / objects.size();
        }
        C* best = &cands[0];
        for (auto& c : cands) if (c.score > best->score) best = &c;
        if (best->score >= kConfidenceThreshold && best->off != off.uobjClass &&
            best->off != off.uobjName) {
            off.uobjOuter = best->off;
            off.record("UObject_Outer", best->off,
                       fmt("vote(%.2f)", best->score), best->score);
        } else {
            off.record("UObject_Outer", off.uobjOuter, "default", std::max(0.f, best->score));
        }
    }

    // ---- UObject.Index -------------------------------------------------------
    if (!ini.has("Offsets", "UObject_Index")) {
        struct C { int off; float score; };
        C cands[] = {{0x0C, 0}, {0x08, 0}};
        for (auto& c : cands) {
            if (c.off == off.uobjFlags) { c.score = -1.0f; continue; }
            usize good = 0;
            for (usize i = 0; i < objects.size(); ++i)
                if (proc.read<i32>(objects[i] + c.off) == indices[i]) ++good;
            c.score = (float)good / objects.size();
        }
        C* best = &cands[0];
        for (auto& c : cands) if (c.score > best->score) best = &c;
        if (best->score >= kConfidenceThreshold) {
            off.uobjIndex = best->off;
            off.record("UObject_Index", best->off,
                       fmt("vote(%.2f)", best->score), best->score);
        } else {
            off.record("UObject_Index", off.uobjIndex, "default", std::max(0.f, best->score));
        }
    }

    // ---- FName::Number placement (IMPORTANT NOTE #2) -------------------------
    if (!ini.has("Offsets", "FNameNumberDelta"))
        probeFNameNumberDelta(proc, off, names, objects);

    return off.uobjClass > 0 && off.uobjName > 0;
}

} // namespace udx::ue
