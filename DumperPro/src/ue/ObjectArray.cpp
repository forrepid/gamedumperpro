// ============================================================================
// DumperPro - GObjects / FUObjectArray parsing with layout auto-detection
//
// Supports UE 4.20-4.27 + UE5.0-5.3 global object arrays:
//   - FChunkedFixedUObjectArray : chunk pointer table + counts      (4.22+ / UE5)
//   - FFixedUObjectArray        : flat (non-chunked) item array     (pre-4.22 / profile)
//
// FUObjectArray global layout (defaults, overridable via UEOffsets):
//   +0x00 ObjFirstGCIndex            +0x04 ObjLastGCIndex
//   +0x08 OpenForDisregardForGC      +0x0C DisregardForGCEnabled (bool, padded)
//   +0x10 ObjObjects:
//          chunked: { FUObjectItem** Chunks; i32 MaxElements; i32 NumElements;
//                     i32 MaxChunks; i32 NumChunks }
//          flat   : { FUObjectItem*  Objects; i32 MaxElements; i32 NumElements }
//
// FUObjectItem: { UObject* Object@0x00; i32 Flags@0x04; i32 ClusterRootIndex@0x08;
//                 i32 SerialNumber@0x0C } -> stride 0x18 (UE4.22+ / UE5),
//                 stride 0x10 on older builds (no serial), 0x20 on padded builds.
// Chunk size: UE4 = 10240 objects/chunk (0x2800), UE5 = 65536 (0x10000).
// ============================================================================
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"
#include "ue/UEVersion.h"
#include "core/MemoryReader.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

namespace dumper {

namespace {

// FUObjectItem: object pointer is always at +0x00 for all known strides
constexpr u32 kItemMinBytes = 0x10;   // { obj, flags, cluster }
constexpr u32 kItemMaxBytes = 0x18;   // { obj, flags, cluster, serial }

constexpr u32    kMaxNumElements  = 60'000'000;
constexpr u32    kMaxChunks       = 4096;
constexpr i32    kMaxSamples      = 64;
constexpr double kMinSampleScore  = 0.95;   // >= 95% of samples must validate

// Count-offset variant: { chunks-ptr, maxElements, numElements, maxChunks, numChunks }
// siblings are derived as ptr+8 etc.
struct CountOffs { u32 ptr, maxE, numE, maxC, numC; };

std::vector<CountOffs> MakeVariants(const UEOffsets& off) {
    std::vector<CountOffs> v;
    auto add = [&](u32 ptr) {
        for (const CountOffs& e : v)
            if (e.ptr == ptr) return;
        v.push_back({ptr, ptr + 8, ptr + 0xC, ptr + 0x10, ptr + 0x14});
    };
    if (off.oaChunksPtrOff) add(off.oaChunksPtrOff);   // profile-derived variant first
    add(0x10);   // primary  {0x10, 0x18, 0x1C, 0x20, 0x24}
    add(0x08);   // shifted  {0x08, 0x10, 0x14, 0x18, 0x1C}
    add(0x18);   // shifted  {0x18, 0x20, 0x24, 0x28, 0x2C}
    return v;
}

std::vector<u32> ChunkSizeCandidates(const UEOffsets& off, const UEVersion& v) {
    std::vector<u32> out;
    auto add = [&](u32 cs) {
        if (!cs) return;
        if (std::find(out.begin(), out.end(), cs) == out.end()) out.push_back(cs);
    };
    add(off.oaChunkSize);                // profile override first
    add(v.IsUE5() ? 65536u : 10240u);    // default for detected version
    add(10240u);
    add(65536u);
    add(16384u);
    add(32768u);
    return out;
}

std::vector<u32> StrideCandidates(const UEOffsets& off) {
    std::vector<u32> out;
    auto add = [&](u32 s) {
        if (!s) return;
        if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
    };
    add(off.oaItemStride);   // profile override first
    add(0x18u);              // UE 4.22+ / UE5 (with SerialNumber)
    add(0x10u);              // pre-4.22 (no SerialNumber)
    add(0x20u);              // padded builds
    return out;
}

// plausible heap pointer: nonzero, 8-aligned, inside user-mode range.
// (module range cannot be checked here without ModuleImage access)
bool PlausiblePtr(u64 p, u64 notEqual = 0) {
    return p != 0 && (p & 7ull) == 0 && p >= 0x10000ull && p < 0x7FFFFFFEFFFFull && p != notEqual;
}

// strongest per-item validation: object ptr, class ptr, name index
bool ItemLooksValid(IMemoryReader& r, const UEOffsets& off, i32 nameCount, u64 gObjectsVA, u64 itemAddr) {
    u64 obj = 0;
    if (!r.ReadPtr(itemAddr, obj)) return false;
    if (!PlausiblePtr(obj, gObjectsVA)) return false;
    if (off.objClassOff) {
        u64 cls = 0;
        if (!r.ReadPtr(obj + off.objClassOff, cls)) return false;
        if (!PlausiblePtr(cls, obj)) return false;
    }
    if (nameCount > 0 && off.objNameOff) {
        i32 nameIdx = 0;
        if (!r.ReadI32(obj + off.objNameOff, nameIdx)) return false;
        if (nameIdx < 0 || nameIdx >= nameCount) return false;
    }
    return true;
}

// fraction [0..1] of valid samples over up to `count` evenly spread indices
double SampleItems(IMemoryReader& r, const UEOffsets& off, i32 nameCount, u64 gObjectsVA,
                   u64 base, u32 stride, bool chunked, u32 chunkSize, i32 numE, i32 count) {
    if (numE <= 0 || stride == 0 || count <= 0) return 0.0;
    if (chunked && chunkSize == 0) return 0.0;
    i32 n = count < kMaxSamples ? count : kMaxSamples;
    if (n > numE) n = numE;
    i32 good = 0;
    for (i32 k = 0; k < n; k++) {
        i64 idx = ((i64)k * (i64)numE) / n;
        if (idx == 0 && numE > 1) idx = 1;   // index 0 is frequently a null/free slot
        u64 itemAddr = 0;
        if (chunked) {
            u64 chunkPtr = 0;
            if (!r.ReadPtr(base + (u64)(idx / (i64)chunkSize) * 8ull, chunkPtr)) continue;
            if (!PlausiblePtr(chunkPtr, gObjectsVA)) continue;
            itemAddr = chunkPtr + (u64)(idx % (i64)chunkSize) * stride;
        } else {
            itemAddr = base + (u64)idx * stride;
        }
        if (ItemLooksValid(r, off, nameCount, gObjectsVA, itemAddr)) good++;
    }
    return (double)good / (double)n;
}

} // namespace

// ---------------------------------------------------------------------------
// init + detection
// ---------------------------------------------------------------------------

bool ObjectArray::TryInit(IMemoryReader& r, UEOffsets& off, const UEVersion& v,
                          const NameArray* names, std::string* err) {
    r_     = &r;
    off_   = &off;
    ver_   = v;
    names_ = names;   // may be null (weaker validation)

    gObjectsVA_ = off.GObjectsVA;   // resolved by SigFinder / profile before TryInit
    ready_      = false;
    num_ = 0; stride_ = 0; chunkSize_ = 0; numChunks_ = 0; flat_ = false;
    chunks_.clear();

    if (!gObjectsVA_) {
        if (err) *err = "no GObjects address (GObjectsVA unresolved)";
        return false;
    }

    std::string detErr;
    if (!DetectLayout(&detErr)) {
        if (err) *err = "GObjects @ " + Hex(gObjectsVA_) + ": " + detErr;
        return false;
    }

    ready_ = true;
    Log::Debug("GObjects ready: %s, num=%d", LayoutInfo().c_str(), num_);
    return true;
}

bool ObjectArray::DetectLayout(std::string* err) {
    num_ = 0;
    flat_ = false;
    stride_ = 0;
    chunkSize_ = 0;
    numChunks_ = 0;
    chunks_.clear();

    std::string lastReason = "no count-offset variant was readable";

    for (const CountOffs& cv : MakeVariants(*off_)) {
        u32 numE = 0, maxE = 0;
        u64 tablePtr = 0;

        if (!r_->ReadU32(gObjectsVA_ + cv.numE, numE) ||
            !r_->ReadU32(gObjectsVA_ + cv.maxE, maxE) ||
            !r_->ReadPtr (gObjectsVA_ + cv.ptr,  tablePtr)) {
            lastReason = "FUObjectArray counts/pointer unreadable";
            Log::Debug("GObjects: variant ptr@0x%X unreadable", cv.ptr);
            continue;
        }
        if (numE < 1 || numE > kMaxNumElements || numE >= 0x7FFFFFFFu || maxE < numE) {
            lastReason = "NumElements implausible: " + Hex32(numE);
            Log::Debug("GObjects: variant ptr@0x%X rejected: %s (maxE=%u)", cv.ptr, lastReason.c_str(), maxE);
            continue;
        }
        if (!PlausiblePtr(tablePtr, gObjectsVA_)) {
            lastReason = "item/chunk table pointer implausible: " + Hex(tablePtr);
            Log::Debug("GObjects: variant ptr@0x%X rejected: %s", cv.ptr, lastReason.c_str());
            continue;
        }

        num_ = (i32)numE;   // sampling context used by SampleValid()

        // ---- chunked path (FChunkedFixedUObjectArray) ----
        auto tryChunked = [&]() -> bool {
            u32 numC = 0, maxC = 0;
            if (!r_->ReadU32(gObjectsVA_ + cv.numC, numC) ||
                !r_->ReadU32(gObjectsVA_ + cv.maxC, maxC)) {
                Log::Debug("GObjects: chunk counts unreadable (variant ptr@0x%X)", cv.ptr);
                return false;
            }
            if (numC < 1 || numC > kMaxChunks || maxC < numC) {
                Log::Debug("GObjects: chunk counts implausible (numC=%u maxC=%u)", numC, maxC);
                return false;
            }
            for (u32 cs : ChunkSizeCandidates(*off_, ver_)) {
                // chunk size is consistent iff numC == ceil(numE/cs) && maxC == ceil(maxE/cs)
                const u64 wantNumC = ((u64)numE + cs - 1) / cs;
                const u64 wantMaxC = ((u64)maxE + cs - 1) / cs;
                if (wantNumC != (u64)numC || wantMaxC != (u64)maxC) {
                    Log::Debug("GObjects: chunk size 0x%X inconsistent (numC=%u want %llu, maxC=%u want %llu)",
                               cs, numC, (unsigned long long)wantNumC,
                               maxC, (unsigned long long)wantMaxC);
                    continue;
                }

                // chunk pointer table: numC qwords, all nonzero + 8-aligned
                std::vector<u64> table((size_t)numC, 0);
                bool got = r_->Read(tablePtr, table.data(), table.size() * sizeof(u64));
                if (!got) {
                    got = true;
                    for (u32 i = 0; i < (u32)numC; i++) {
                        if (!r_->ReadPtr(tablePtr + (u64)i * 8ull, table[i])) { got = false; break; }
                    }
                }
                if (!got) {
                    Log::Debug("GObjects: chunk table unreadable @ %s", Hex(tablePtr).c_str());
                    continue;
                }
                bool tableSane = true;
                for (u64 c : table) {
                    if (!PlausiblePtr(c, gObjectsVA_)) { tableSane = false; break; }
                }
                if (!tableSane) {
                    Log::Debug("GObjects: chunk table has implausible entries");
                    continue;
                }

                // stride sampling: >= 95% valid; prefer higher consistency, ties -> 0x18
                double best = 0.0;
                u32 bestStride = 0;
                for (u32 s : StrideCandidates(*off_)) {
                    const double score = SampleValid(tablePtr, s, true, cs, kMaxSamples);
                    Log::Debug("GObjects: chunked cs=0x%X stride=0x%X -> %.1f%% valid", cs, s, score * 100.0);
                    if (score >= kMinSampleScore && score > best) { best = score; bestStride = s; }
                }
                if (!bestStride) {
                    Log::Debug("GObjects: no stride passed sampling for chunk size 0x%X", cs);
                    continue;
                }

                flat_      = false;
                stride_    = bestStride;
                chunkSize_ = cs;
                numChunks_ = (i32)numC;
                num_       = (i32)numE;
                chunks_    = std::move(table);
                return true;
            }
            return false;
        };

        // ---- flat path (FFixedUObjectArray): tablePtr points directly at items ----
        auto tryFlat = [&]() -> bool {
            double best = 0.0;
            u32 bestStride = 0;
            for (u32 s : StrideCandidates(*off_)) {
                const double score = SampleValid(tablePtr, s, false, 0, kMaxSamples);
                Log::Debug("GObjects: flat stride=0x%X -> %.1f%% valid", s, score * 100.0);
                if (score >= kMinSampleScore && score > best) { best = score; bestStride = s; }
            }
            if (!bestStride) return false;
            flat_      = true;
            stride_    = bestStride;
            chunkSize_ = 0;
            numChunks_ = 1;
            num_       = (i32)numE;
            chunks_.assign(1, tablePtr);   // chunks_[0] = flat item array base
            return true;
        };

        // profile can prefer the flat layout; the other path stays as fallback
        const bool ok = off_->oaFlat ? (tryFlat() || tryChunked())
                                     : (tryChunked() || tryFlat());
        if (ok) return true;
    }

    num_ = 0;
    if (err) *err = "no FUObjectArray layout variant validated (" + lastReason + ")";
    return false;
}

// ---------------------------------------------------------------------------
// accessors
// ---------------------------------------------------------------------------

u64 ObjectArray::ItemAddr(i32 index) const {
    if (index < 0 || (u64)index >= (u64)num_ || stride_ == 0) return 0;
    if (flat_) {
        if (chunks_.empty()) return 0;
        return chunks_[0] + (u64)index * stride_;
    }
    if (chunkSize_ == 0) return 0;
    const i64 chunkIdx = index / (i64)chunkSize_;
    if (chunkIdx < 0 || (size_t)chunkIdx >= chunks_.size()) return 0;
    return chunks_[(size_t)chunkIdx] + (u64)(index % (i32)chunkSize_) * stride_;
}

ObjItem ObjectArray::At(i32 index) const {
    ObjItem it;
    it.index = index;
    if (!r_ || !ready_) return it;

    const u64 addr = ItemAddr(index);
    it.itemAddr = addr;
    if (!addr) return it;

    // parse item fields per stride: 0x18 -> {obj, flags, cluster, serial}, 0x10 -> {obj, flags, cluster}
    const u32 raw = stride_ >= kItemMaxBytes ? kItemMaxBytes : kItemMinBytes;
    u8 buf[kItemMaxBytes] = {};
    if (!r_->Read(addr, buf, raw)) return it;   // read failure -> zeroed fields

    u64 obj = 0;
    i32 flags = 0, cluster = 0, serial = 0;
    memcpy(&obj,     buf + 0x00, sizeof(obj));
    memcpy(&flags,   buf + 0x04, sizeof(flags));
    memcpy(&cluster, buf + 0x08, sizeof(cluster));
    if (raw >= kItemMaxBytes) memcpy(&serial, buf + 0x0C, sizeof(serial));

    it.objectAddr  = obj;
    it.flags       = flags;
    it.clusterRoot = cluster;
    it.serialNumber = serial;
    return it;
}

u64 ObjectArray::ObjectAt(i32 index) const {
    return At(index).objectAddr;
}

bool ObjectArray::ValidateIndex(i32 index) const {
    if (index < 0 || (u64)index >= (u64)num_) return false;
    return At(index).objectAddr != 0;
}

std::string ObjectArray::LayoutInfo() const {
    if (!ready_) return "not initialized";
    char buf[96];
    if (flat_) {
        snprintf(buf, sizeof(buf), "flat stride=0x%X", stride_);
    } else {
        snprintf(buf, sizeof(buf), "chunked stride=0x%X chunk=0x%X chunks=%d", stride_, chunkSize_, numChunks_);
    }
    return buf;
}

// ---------------------------------------------------------------------------
// static candidate validation (used by SigFinder)
// ---------------------------------------------------------------------------

bool ObjectArray::ValidateCandidate(IMemoryReader& r, UEOffsets& off, const UEVersion& v,
                                    u64 gObjectsVA, i32 nameCount, std::string* why) {
    auto reject = [&](const std::string& m) {
        if (why && why->empty()) *why = m;   // keep the first concrete failure
        Log::Debug("GObjects candidate @ %s rejected: %s", Hex(gObjectsVA).c_str(), m.c_str());
        return false;
    };

    if (!gObjectsVA) return reject("null GObjects address");

    for (const CountOffs& cv : MakeVariants(off)) {
        u32 numE = 0, maxE = 0, numC = 0, maxC = 0;
        u64 tablePtr = 0;
        const bool readable = r.ReadU32(gObjectsVA + cv.numE, numE) &&
                              r.ReadU32(gObjectsVA + cv.maxE, maxE) &&
                              r.ReadU32(gObjectsVA + cv.numC, numC) &&
                              r.ReadU32(gObjectsVA + cv.maxC, maxC) &&
                              r.ReadPtr (gObjectsVA + cv.ptr,  tablePtr);
        if (!readable) { reject("FUObjectArray counts unreadable"); continue; }
        if (numE < 1 || numE > kMaxNumElements || numE >= 0x7FFFFFFFu || maxE < numE) {
            reject("NumElements implausible: " + Hex32(numE));
            continue;
        }
        if (!PlausiblePtr(tablePtr, gObjectsVA)) {
            reject("item/chunk table pointer implausible: " + Hex(tablePtr));
            continue;
        }

        double bestScore = 0.0;

        // quick chunked check: counts sane + chunk size consistent + table sane + samples
        if (numC >= 1 && numC <= kMaxChunks && maxC >= numC) {
            for (u32 cs : ChunkSizeCandidates(off, v)) {
                if (((u64)numE + cs - 1) / cs != (u64)numC ||
                    ((u64)maxE + cs - 1) / cs != (u64)maxC) continue;
                std::vector<u64> table((size_t)numC, 0);
                if (!r.Read(tablePtr, table.data(), table.size() * sizeof(u64))) {
                    reject("chunk table unreadable");
                    continue;
                }
                bool tableSane = true;
                for (u64 c : table) {
                    if (!PlausiblePtr(c, gObjectsVA)) { tableSane = false; break; }
                }
                if (!tableSane) { reject("chunk table has implausible entries"); continue; }

                for (u32 s : StrideCandidates(off)) {
                    const double score = SampleItems(r, off, nameCount, gObjectsVA,
                                                     tablePtr, s, true, cs, (i32)numE, 20);
                    if (score >= kMinSampleScore) return true;
                    if (score > bestScore) bestScore = score;
                }
            }
        }

        // quick flat check: tablePtr is the direct item array base
        for (u32 s : StrideCandidates(off)) {
            const double score = SampleItems(r, off, nameCount, gObjectsVA,
                                             tablePtr, s, false, 0, (i32)numE, 20);
            if (score >= kMinSampleScore) return true;
            if (score > bestScore) bestScore = score;
        }

        if (bestScore > 0.0) {
            char buf[64];
            const int good = (int)(bestScore * 20.0 + 0.5);
            snprintf(buf, sizeof(buf), "sampled objects invalid (%d/20)", 20 - good);
            reject(buf);
        }
    }

    return reject("no FUObjectArray layout variant validated");
}

// ---------------------------------------------------------------------------
// member sampling helper (delegates to the shared stateless sampler)
// ---------------------------------------------------------------------------

double ObjectArray::SampleValid(u64 base, u32 stride, bool chunked, u32 chunkSize, i32 count) {
    if (!r_ || !off_) return 0.0;
    const i32 nameCount = names_ ? names_->Num() : 0;
    return SampleItems(*r_, *off_, nameCount, gObjectsVA_, base, stride, chunked, chunkSize, num_, count);
}

} // namespace dumper
