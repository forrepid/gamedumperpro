// ============================================================================
//  UnrealDumperX - fname.cpp
// ============================================================================
#include "fname.h"
#include "ini.h"
#include "log.h"

namespace udx::ue {

// ---------------------------------------------------------------------------
// Entry decoding - shared with the finder (exported, see fname.h).
// Handles both ANSICHAR and WIDECHAR payloads (IMPORTANT NOTE #3).
// ---------------------------------------------------------------------------
bool decodeEntryAt(Process& proc, uintptr_t entryAddr, int headerSize,
                   int lenShift, std::string& out) {
    if (!entryAddr || !proc.ptrReadable(entryAddr)) return false;
    const u32 header = proc.read<u32>(entryAddr);
    if (!header) return false;

    bool wide = false;
    int len = 0;
    if (headerSize == 2) {
        const u16 h = (u16)header;
        wide = (h & 1) != 0;                       // bIsWide @ bit0
        len = (int)(h >> lenShift) & 0x3FF;        // 10/15 bit length field
    } else {
        wide = ((header >> 31) & 1) != 0;          // old uint32 header
        len = (int)((header >> 6) & 0x3FF);
    }
    if (len <= 0 || len > 1024) return false;

    const uintptr_t data = entryAddr + (usize)headerSize;
    if (wide) {
        std::vector<u16> chars(len);
        if (!proc.read(data, chars.data(), len * sizeof(u16))) return false;
        out.assign(wideToUtf8(std::wstring(chars.begin(), chars.end())));
    } else {
        std::vector<u8> chars(len);
        if (!proc.read(data, chars.data(), len)) return false;
        out.assign(chars.begin(), chars.end());
    }
    for (char c : out)
        if (c != '\0' && c < 0x20 && c != '\t') return false;
    return !out.empty();
}

namespace {
// Iterates pool indices, stopping at the first invalid block.
usize drainPool(Process& proc, const Offsets& off, std::vector<std::string>& out,
                log::Progress* progress) {
    usize idx = 0;
    usize badStreak = 0;
    constexpr usize kMaxNames = 2u * 1024 * 1024;
    while (idx < kMaxNames) {
        const u32 blockIdx = (u32)(idx >> off.nameChunkBits);
        if (blockIdx >= (u32)off.nameMaxBlocks) break;
        const uintptr_t block = proc.read<u64>(off.gNames + off.nameBlocksOffset +
                                               (u64)blockIdx * 8);
        if (!block || !proc.ptrReadable(block)) break;
        const u32 inBlock = (u32)(idx & ((1u << off.nameChunkBits) - 1));
        const uintptr_t entry = block + (u64)inBlock * (usize)off.nameStride;
        std::string name;
        if (decodeEntryAt(proc, entry, off.nameHeaderSize, off.nameLenShift, name)) {
            out.push_back(std::move(name));
            badStreak = 0;
        } else {
            out.push_back({});
            if (++badStreak >= 256) break;
        }
        if (progress && (idx & 0xFFF) == 0) progress->update(idx);
        ++idx;
    }
    if (progress) progress->done(fmt("FName havuzu: %zu isim okundu", out.size()));
    return out.size();
}

} // namespace

// ---------------------------------------------------------------------------
// Single-entry read (used by validators before the full pool is loaded)
// ---------------------------------------------------------------------------
bool readFNameEntry(Process& proc, const Offsets& off, u32 index,
                    std::string& out) {
    if (!off.gNames) return false;
    if (off.nameStride == 0) {
        // TNameEntryArray: indirect pointers.
        const u32 chunk = index >> off.nameChunkBits;
        const uintptr_t chunkPtr = proc.read<u64>(off.gNames + (u64)chunk * 8);
        if (!chunkPtr) return false;
        const uintptr_t entryPtr =
            proc.read<u64>(chunkPtr + (u64)(index & ((1u << off.nameChunkBits) - 1)) * 8);
        return decodeEntryAt(proc, entryPtr, off.nameHeaderSize, off.nameLenShift, out);
    }
    const u32 blockIdx = index >> off.nameChunkBits;
    const uintptr_t block =
        proc.read<u64>(off.gNames + off.nameBlocksOffset + (u64)blockIdx * 8);
    if (!block) return false;
    const uintptr_t entry =
        block + (u64)(index & ((1u << off.nameChunkBits) - 1)) * (usize)off.nameStride;
    return decodeEntryAt(proc, entry, off.nameHeaderSize, off.nameLenShift, out);
}

FNameValue readFName(Process& proc, const Offsets& off, u64 nameAddr) {
    FNameValue v;
    v.index = proc.read<u32>(nameAddr);
    // IMPORTANT NOTE #2: Number sits at +0x04 (UE5) or -0x04 (UE4 builds).
    v.number = proc.read<i32>((i64)(i32)off.fNameNumberDelta >= 0
                                  ? nameAddr + (u64)off.fNameNumberDelta
                                  : nameAddr - (u64)(-(i64)off.fNameNumberDelta));
    return v;
}

// ---------------------------------------------------------------------------
// FNamePool (4.23+ / UE5)
// ---------------------------------------------------------------------------
bool NameDb::initFNamePool(Process& proc, Offsets& off) {
    static const int kBlockOffsets[] = {0x10, 0x08, 0x00, 0x18, 0x20};
    static const int kStrides[] = {2, 4};
    static const int kLenShifts[] = {6, 1};

    const bool pinnedBlocks = off.metaFor("NameBlocksOffset").source == "ini";
    const bool pinnedStride = off.metaFor("NameStride").source == "ini";
    const bool pinnedShift  = off.metaFor("NameLenShift").source == "ini";

    if (pinnedBlocks && pinnedStride && pinnedShift) {
        // Fully pinned by games.ini - validate entry #0 == "None" only.
        std::string name;
        if (readFNameEntry(proc, off, 0, name) && name == "None") {
            note_ = "games.ini pinned layout";
            return true;
        }
        log::warn("games.ini FName sablonu dogrulanamadi (entry#0 != \"None\")");
    }

    // Auto-calibration: entry #0 must be "None", entry #1 must be "ByteProperty".
    for (int blocksOff : kBlockOffsets) {
        const uintptr_t block0 =
            proc.read<u64>(off.gNames + blocksOff);
        if (!block0 || !proc.ptrReadable(block0)) continue;
        for (int stride : kStrides) {
            for (int shift : kLenShifts) {
                std::string n0, n1;
                if (!decodeEntryAt(proc, block0, 2, shift, n0)) continue;
                if (n0 != "None") continue;
                if (!decodeEntryAt(proc, block0 + (usize)stride, 2, shift, n1)) continue;
                if (n1 != "ByteProperty") continue;
                off.nameBlocksOffset = blocksOff;
                off.nameStride = stride;
                off.nameLenShift = shift;
                off.nameHeaderSize = 2;
                off.nameChunkBits = 16;
                off.record("NameBlocksOffset", blocksOff, "probe", 1.0f);
                off.record("NameStride", stride, "probe", 1.0f);
                off.record("NameLenShift", shift, "probe", 1.0f);
                note_ = fmt("auto: Blocks@0x%X stride=%d shift=%d",
                            blocksOff, stride, shift);
                log::ok("FNamePool kalibrasyonu: " + note_);
                return true;
            }
        }
    }
    log::warn("FNamePool kalibrasyonu basarisiz - games.ini degerleriyle deneniyor");
    return pinnedBlocks;
}

// ---------------------------------------------------------------------------
// TNameEntryArray (4.20 - 4.22)
// ---------------------------------------------------------------------------
bool NameDb::initIndirectArray(Process& proc, Offsets& off) {
    // Chunk pointer table starts at GNames + 0; probe the header size.
    const uintptr_t chunk0 = proc.read<u64>(off.gNames);
    if (!chunk0 || !proc.ptrReadable(chunk0)) return false;
    const uintptr_t entry0 = proc.read<u64>(chunk0);
    if (!entry0) return false;

    for (int hdrSize : {4, 2}) {
        std::string n0;
        if (!decodeEntryAt(proc, entry0, hdrSize, 6, n0)) continue;
        if (n0 != "None") continue;
        off.nameHeaderSize = hdrSize;
        off.nameLenShift = 6;
        off.nameChunkBits = 14;
        off.nameStride = 0;
        off.record("NameHeaderSize", hdrSize, "probe", 1.0f);
        note_ = fmt("indirect array: header=%d", hdrSize);
        log::ok("TNameEntryArray kalibrasyonu: " + note_);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Full load
// ---------------------------------------------------------------------------
bool NameDb::init(Process& proc, Offsets& off, UEVersion ver, const Ini& ini) {
    if (!off.gNames) {
        log::error("GNames adresi yok - isim havuzu okunamadi");
        return false;
    }
    off.applyDefaultsFor(ver);
    off.applyIni(ini);

    const bool usePool = usesFNamePool(ver) &&
                         !(usesIndirectArray(ver) && !isUE5(ver) &&
                           off.metaFor("NameHeaderSize").source == "ini");
    poolMode_ = usePool ? initFNamePool(proc, off)
                        : (usesIndirectArray(ver) ? initIndirectArray(proc, off)
                                                  : initFNamePool(proc, off));
    if (!poolMode_) return false;

    // Count hint for the progress bar: scan block pointers while draining.
    log::Progress progress("FName pool", 1u << 21);
    drainPool(proc, off, names_, &progress);
    log::ok(fmt("%zu FName okundu (%s)", names_.size(),
                poolMode_ ? "FNamePool" : "TNameEntryArray"));
    return !names_.empty();
}

std::string NameDb::get(u32 index) const {
    return index < names_.size() ? names_[index] : std::string();
}

} // namespace udx::ue
