// ============================================================================
// DumperPro - GNames / FNamePool parsing
//
// Primary mode  : UE4.23+ / UE5 FNamePool
//   +0x00 locks (8 bytes)          +0x08 uint32 CurrentBlock
//   +0x0C uint32 CurrentByteCursor +0x10 uint8* Blocks[8192]
//   Block size 0x10000 (UE4) / 0x20000 (UE5)
//   Entry header u16: bit0 = bIsWide, len = header >> 6 (max 1023)
//   Entry stride = AlignUp(2 + len * (wide ? 2 : 1), entryAlign), align 2 or 4
//
// Fallback mode : UE4.20-4.22 legacy TNameEntryArray (chunked, best effort)
//   chunk pointer table inline at +0x00 (16384 entries/chunk), NumElements @ +0x400
// ============================================================================
#include "ue/NameArray.h"
#include "ue/UEVersion.h"
#include "core/MemoryReader.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"
#include "utils/Progress.h"

namespace dumper {

namespace {

constexpr u32 kMaxBlocks     = 0x4000;
constexpr u32 kMaxNames      = 3'000'000;
constexpr u32 kMaxNameLen    = 1023;
constexpr u32 kMinNamesValid = 16;

bool PlausibleHeapPtr(u64 p) {
    return p != 0 && (p & 7ull) == 0 && p >= 0x10000ull && p < 0x7FFFFFFEFFFFull;
}

struct EntryWalk {
    u32 count = 0;
    u32 bad = 0;
    u32 lastOff = 0;
};

// Walk variable-length name entries inside a LOCAL block buffer.
// lenShift: 6 = FNamePool header (probe hash bits), 1 = legacy header.
// strictWide: probe mode - also flag implausible wide entries as bad (a real
// pool's first block contains only ANSI core names, so garbage data that
// smuggles itself through as "wide" entries gets rejected; 1b regression,
// real UE5.1 shipping binary, 2026-11-20).
EntryWalk WalkEntriesLocal(const u8* data, u32 size, u32 entryAlign, u32 lenShift,
                           std::vector<std::string>* sink, u32 maxEntries,
                           bool strictWide = false) {
    EntryWalk w;
    u32 off = 0;
    while (off + 2 <= size && (maxEntries == 0 || w.count < maxEntries)) {
        u16 h = 0;
        memcpy(&h, data + off, 2);
        const bool wide = (h & 1) != 0;
        const u32 len = (u32)h >> lenShift;
        if (len > kMaxNameLen) { w.bad++; w.lastOff = off; break; }

        const size_t charSz = wide ? 2 : 1;
        const size_t dataBytes = (size_t)len * charSz;
        if ((size_t)off + 2 + dataBytes > size) { w.bad++; w.lastOff = off; break; }

        if (sink) {
            if (wide) {
                std::vector<u16> buf(len);
                memcpy(buf.data(), data + off + 2, dataBytes);
                sink->push_back(str::WideToUtf8(buf.data(), len));
            } else {
                sink->push_back(std::string((const char*)data + off + 2, len));
            }
        }
        if (len > 0 && !wide && !str::IsPrintableAscii((const char*)data + off + 2, dataBytes)) {
            w.bad++;
        }
        if (len > 0 && wide && strictWide) {
            // probe mode: a plausible wide name is printable ASCII (non-ASCII
            // wide names never appear in a pool's FIRST block)
            const u16* ch = (const u16*)(data + off + 2);
            bool plausible = true;
            for (size_t i = 0; i < (size_t)len; i++) {
                if (ch[i] < 0x20 || ch[i] > 0x7E) { plausible = false; break; }
            }
            if (!plausible) w.bad++;
        }
        w.count++;
        w.lastOff = off;
        const u64 stride = str::AlignUp(2 + dataBytes, entryAlign ? entryAlign : 1);
        if (stride < 2) break;
        off = off + (u32)stride;
        if (off < w.lastOff) break; // overflow guard
    }
    return w;
}

// First-block probe used for both init and candidate validation.
// Returns true if at least one (blockSize, align, lenShift) combo walks cleanly.
bool ProbeFirstBlock(IMemoryReader& r, u64 gNamesVA, u32 blockSize, u32 entryAlign,
                     u32 lenShift, std::string* why) {
    u64 block0 = 0;
    if (!r.ReadPtr(gNamesVA + 0x10, block0) || !PlausibleHeapPtr(block0)) {
        if (why && why->empty()) *why = "first block pointer implausible";
        return false;
    }
    u8 buf[0x400];
    const u32 n = (u32)sizeof(buf);
    if (!r.Read(block0, buf, n)) {
        if (why && why->empty()) *why = "first block unreadable";
        return false;
    }
    // "None" anchor: FName index 0 of every UE name pool is "None" (created
    // first by FName's static init). A candidate whose first entry does not
    // decode to ANSI "None" is a false positive - garbage .data cannot fake
    // this anchor. Applies to the FNamePool header (lenShift 6) only.
    if (lenShift == 6) {
        u16 h0 = 0;
        memcpy(&h0, buf, 2);
        const u32 len0 = (u32)h0 >> lenShift;
        if ((h0 & 1) || len0 != 4 || memcmp(buf + 2, "None", 4) != 0) {
            if (why && why->empty()) *why = "first entry is not ANSI 'None' (pool anchor)";
            return false;
        }
    }
    EntryWalk w = WalkEntriesLocal(buf, n, entryAlign, lenShift, nullptr, 40, true);
    if (w.count < 8) {
        if (why && why->empty()) *why = "too few entries in first block";
        return false;
    }
    if (w.bad != 0) {
        if (why && why->empty()) *why = "invalid entries in first block (" + std::to_string(w.bad) + ")";
        return false;
    }
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

bool NameArray::TryInit(IMemoryReader& r, UEOffsets& off, const UEVersion& v, std::string* err) {
    r_ = &r;
    off_ = &off;
    ver_ = v;
    ready_ = false;
    names_.clear();

    gNamesVA_ = off.GNamesVA;   // resolved by SigFinder / profile before TryInit
    if (!gNamesVA_) {
        if (err) *err = "no GNames address (GNamesVA unresolved)";
        return false;
    }

    std::string poolErr, legacyErr;
    if (ReadAsPool(&poolErr)) {
        poolMode_ = true;
        ready_ = true;
        Log::Debug("GNames: pool mode OK (%s)", ModeInfo().c_str());
        return true;
    }
    Log::Debug("GNames: pool mode failed: %s", poolErr.c_str());

    if (ReadAsLegacy(&legacyErr)) {
        poolMode_ = false;
        ready_ = true;
        Log::Debug("GNames: legacy mode OK (%s)", ModeInfo().c_str());
        return true;
    }
    Log::Debug("GNames: legacy mode failed: %s", legacyErr.c_str());

    if (err) *err = "pool: " + poolErr + " | legacy: " + legacyErr;
    return false;
}

// ---------------------------------------------------------------------------
// FNamePool
// ---------------------------------------------------------------------------

bool NameArray::ReadAsPool(std::string* err) {
    u32 currentBlock = 0, cursor = 0;
    if (!r_->ReadU32(gNamesVA_ + 0x08, currentBlock) || !r_->ReadU32(gNamesVA_ + 0x0C, cursor)) {
        if (err) *err = "FNamePool header unreadable";
        return false;
    }
    if (currentBlock < 1 || currentBlock > kMaxBlocks) {
        if (err) *err = "CurrentBlock implausible: " + Hex32(currentBlock);
        return false;
    }

    // candidate (blockSize, entryAlign) combos, best-first for the detected era
    std::vector<std::pair<u32, u32>> combos;
    auto addCombo = [&](u32 bs, u32 al) {
        for (const auto& c : combos)
            if (c.first == bs && c.second == al) return;
        combos.push_back({bs, al});
    };
    addCombo(ver_.IsUE5() ? 0x20000u : 0x10000u, ver_.IsUE5() ? 4u : 2u);
    addCombo(0x20000u, 4u);
    addCombo(0x20000u, 2u);
    addCombo(0x10000u, 4u);
    addCombo(0x10000u, 2u);

    bool picked = false;
    for (const auto& c : combos) {
        if (c.second == 0 || c.second > c.first) continue;
        if (cursor > c.first) continue;
        std::string why;
        if (ProbeFirstBlock(*r_, gNamesVA_, c.first, c.second, 6, &why)) {
            blockSize_ = c.first;
            entryAlign_ = c.second;
            picked = true;
            break;
        }
        Log::Debug("GNames pool: bs=0x%X align=%u rejected: %s", c.first, c.second, why.c_str());
    }
    if (!picked) {
        if (err) *err = "no (blockSize, align) combo validated";
        return false;
    }

    // read block pointer table
    std::vector<u64> blocks(currentBlock, 0);
    if (!r_->Read(gNamesVA_ + 0x10, blocks.data(), blocks.size() * sizeof(u64))) {
        for (u32 i = 0; i < currentBlock; i++) {
            if (!r_->ReadPtr(gNamesVA_ + 0x10 + (u64)i * 8ull, blocks[i])) {
                if (err) *err = "block pointer table unreadable at block " + std::to_string(i);
                return false;
            }
        }
    }

    names_.reserve(std::min<u64>((u64)currentBlock * 4096ull, (u64)kMaxNames));

    Progress p("GNames", (u64)currentBlock);
    for (u32 b = 0; b < currentBlock; b++) {
        if (PlausibleHeapPtr(blocks[b])) {
            const u32 used = (b == currentBlock - 1) ? std::min<u32>(cursor, blockSize_) : blockSize_;
            u8 local[0x20000];
            const u32 n = std::min<u32>(used ? used : blockSize_, (u32)sizeof(local));
            if (r_->Read(blocks[b], local, n)) {
                WalkEntriesLocal(local, n, entryAlign_, 6, &names_, 0);
            } else {
                Log::Debug("GNames: block %u unreadable", b);
            }
        } else {
            Log::Debug("GNames: block %u pointer implausible (%s)", b, Hex(blocks[b]).c_str());
        }
        p.Add();
        if (names_.size() >= kMaxNames) break;
    }
    p.Done(std::to_string(names_.size()) + " names");

    if (names_.size() < kMinNamesValid) {
        if (err) *err = "pool produced too few names (" + std::to_string(names_.size()) + ")";
        names_.clear();
        return false;
    }
    return true;
}

void NameArray::ReadPoolBlock(u64 blockPtr, u32 usedSize, u32 entryAlign, u32& outEntries, u32& outBad) {
    (void)blockPtr;
    u8 local[0x20000];
    const u32 n = std::min<u32>(usedSize ? usedSize : blockSize_, (u32)sizeof(local));
    if (!r_->Read(blockPtr, local, n)) {
        outEntries = 0;
        outBad = 1;
        return;
    }
    EntryWalk w = WalkEntriesLocal(local, n, entryAlign, 6, &names_, 0);
    outEntries = w.count;
    outBad = w.bad;
}

// ---------------------------------------------------------------------------
// Legacy TNameEntryArray (UE 4.20 - 4.22, best effort)
// ---------------------------------------------------------------------------

bool NameArray::ReadAsLegacy(std::string* err) {
    u32 numE = 0;
    if (!r_->ReadU32(gNamesVA_ + 0x400, numE)) {
        if (err) *err = "legacy NumElements unreadable";
        return false;
    }
    if (numE < 1 || numE > 3'000'000) {
        if (err) *err = "legacy NumElements implausible: " + Hex32(numE);
        return false;
    }

    constexpr u32 kEntriesPerChunk = 16384;
    const u32 chunkCount = (numE + kEntriesPerChunk - 1) / kEntriesPerChunk;
    if (chunkCount > 128) {
        if (err) *err = "legacy chunk count too high";
        return false;
    }

    std::vector<u64> chunks(chunkCount, 0);
    if (!r_->Read(gNamesVA_, chunks.data(), chunks.size() * sizeof(u64))) {
        for (u32 i = 0; i < chunkCount; i++) {
            if (!r_->ReadPtr(gNamesVA_ + (u64)i * 8ull, chunks[i])) {
                if (err) *err = "legacy chunk table unreadable";
                return false;
            }
        }
    }
    for (u64 c : chunks) {
        if (!PlausibleHeapPtr(c)) {
            if (err) *err = "legacy chunk pointer implausible";
            return false;
        }
    }

    // validate a parse variant on chunk 0
    struct Variant { u32 chunkBytes; u32 align; u32 lenShift; };
    std::vector<Variant> variants = {
        {0x10000, 2, 1}, {0x10000, 2, 6},
        {0xFF00,  2, 1}, {0xFF00,  2, 6},
        {0x20000, 2, 1}, {0x20000, 2, 6},
    };
    Variant picked{};
    bool ok = false;
    u8 probe[0x400];
    for (const Variant& var : variants) {
        if (!r_->Read(chunks[0], probe, (u32)sizeof(probe))) break;
        EntryWalk w = WalkEntriesLocal(probe, (u32)sizeof(probe), var.align, var.lenShift, nullptr, 40);
        if (w.count >= 8 && w.bad == 0) {
            picked = var;
            ok = true;
            break;
        }
    }
    if (!ok) {
        if (err) *err = "no legacy entry layout validated";
        return false;
    }

    Progress p("GNames", (u64)chunkCount);
    for (u32 c = 0; c < chunkCount; c++) {
        u8 local[0x20000];
        const u32 n = std::min<u32>(picked.chunkBytes, (u32)sizeof(local));
        if (r_->Read(chunks[c], local, n)) {
            EntryWalk w = WalkEntriesLocal(local, n, picked.align, picked.lenShift, &names_, 0);
            if (w.bad > 0 && c > 0) break; // trailing garbage on later chunks
        }
        p.Add();
        if (names_.size() >= kMaxNames) break;
    }
    p.Done(std::to_string(names_.size()) + " names (legacy)");

    if (names_.size() < kMinNamesValid) {
        if (err) *err = "legacy produced too few names (" + std::to_string(names_.size()) + ")";
        names_.clear();
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// accessors + validation
// ---------------------------------------------------------------------------

std::string NameArray::Get(i32 idx) const {
    if (idx < 0 || (size_t)idx >= names_.size()) return "";
    return names_[(size_t)idx];
}

std::string NameArray::ModeInfo() const {
    if (!ready_) return "not initialized";
    char buf[96];
    if (poolMode_) {
        snprintf(buf, sizeof(buf), "FNamePool bs=0x%X align=%u", blockSize_, entryAlign_);
    } else {
        snprintf(buf, sizeof(buf), "Legacy TNameEntryArray align=%u", entryAlign_);
    }
    return buf;
}

bool NameArray::ValidateCandidate(IMemoryReader& r, UEOffsets& off, const UEVersion& v,
                                  u64 gNamesVA, std::string* why) {
    (void)off;
    (void)v;
    auto reject = [&](const std::string& m) {
        if (why && why->empty()) *why = m;
        Log::Debug("GNames candidate @ %s rejected: %s", Hex(gNamesVA).c_str(), m.c_str());
        return false;
    };

    if (!gNamesVA) return reject("null GNames address");

    u32 currentBlock = 0, cursor = 0;
    if (!r.ReadU32(gNamesVA + 0x08, currentBlock) || !r.ReadU32(gNamesVA + 0x0C, cursor)) {
        return reject("FNamePool header unreadable");
    }
    if (currentBlock < 1 || currentBlock > kMaxBlocks) {
        return reject("CurrentBlock implausible: " + Hex32(currentBlock));
    }

    for (u32 bs : {0x10000u, 0x20000u}) {
        for (u32 al : {4u, 2u}) {
            if (al > bs) continue;
            std::string m;
            if (ProbeFirstBlock(r, gNamesVA, bs, al, 6, &m)) {
                Log::Debug("GNames candidate @ %s VALID (bs=0x%X align=%u)",
                           Hex(gNamesVA).c_str(), bs, al);
                return true;
            }
        }
    }
    return reject("first block did not validate as FNamePool");
}

} // namespace dumper
