// ============================================================================
//  UnrealDumperX - pattern.cpp
// ============================================================================
#include "pattern.h"

namespace udx {

static u8 hexNibble(char c) {
    if (c >= '0' && c <= '9') return (u8)(c - '0');
    if (c >= 'a' && c <= 'f') return (u8)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (u8)(c - 'A' + 10);
    return 0xFF;
}

Pattern parseIda(const std::string& sig) {
    Pattern p;
    for (usize i = 0; i < sig.size();) {
        while (i < sig.size() && (sig[i] == ' ' || sig[i] == '\t')) ++i;
        if (i >= sig.size()) break;
        const char c0 = sig[i], c1 = (i + 1 < sig.size()) ? sig[i + 1] : '\0';
        if (c0 == '?' ) {                       // "?" or "??"
            p.bytes.push_back(0);
            p.mask.push_back(false);
            i += 1 + (c1 == '?' ? 1 : 0);
            continue;
        }
        const u8 hi = hexNibble(c0), lo = (c1 != '\0') ? hexNibble(c1) : 0xFF;
        if (hi == 0xFF || lo == 0xFF) break;    // malformed - stop
        p.bytes.push_back((u8)(hi << 4 | lo));
        p.mask.push_back(true);
        i += 2;
    }
    return p;
}

std::string patternToString(const Pattern& p) {
    std::string out;
    for (usize i = 0; i < p.bytes.size(); ++i) {
        if (i) out += ' ';
        if (p.mask[i]) out += fmt("%02X", p.bytes[i]);
        else           out += "??";
    }
    return out;
}

// Reads a module image into memory (page-granular; unreadable pages -> 0).
static std::vector<u8> readModuleImage(Process& proc, const ModuleInfo& mod) {
    std::vector<u8> buf(mod.size ? mod.size : 1, 0);
    usize done = 0;
    while (done < buf.size()) {
        const uintptr_t cur = mod.base + done;
        const usize chunk = std::min<usize>(0x1000 - (cur & 0xFFF), buf.size() - done);
        if (!proc.read(cur, buf.data() + done, chunk))
            std::memset(buf.data() + done, 0, chunk);
        done += chunk;
    }
    return buf;
}

static bool matchAt(const std::vector<u8>& buf, usize pos, const Pattern& p) {
    if (pos + p.length() > buf.size()) return false;
    for (usize i = 0; i < p.length(); ++i)
        if (p.mask[i] && buf[pos + i] != p.bytes[i]) return false;
    return true;
}

uintptr_t scanModule(Process& proc, const ModuleInfo& mod, const Pattern& pat) {
    if (pat.empty()) return 0;
    const auto buf = readModuleImage(proc, mod);
    // Skip-list: jump straight to the next occurrence of a masked first byte.
    u8 first = 0; bool haveFirst = false;
    for (usize i = 0; i < pat.length(); ++i)
        if (pat.mask[i]) { first = pat.bytes[i]; haveFirst = true; break; }
    for (usize i = 0; i + pat.length() <= buf.size(); ++i) {
        if (haveFirst && buf[i] != first) continue;
        if (matchAt(buf, i, pat)) return mod.base + i;
    }
    return 0;
}

std::vector<uintptr_t> scanModuleAll(Process& proc, const ModuleInfo& mod,
                                     const Pattern& pat, usize maxHits) {
    std::vector<u64> hits;
    if (pat.empty()) return {};
    const auto buf = readModuleImage(proc, mod);
    for (usize i = 0; i + pat.length() <= buf.size() && hits.size() < maxHits; ++i)
        if (matchAt(buf, i, pat)) hits.push_back(mod.base + i);
    return hits;
}

std::vector<uintptr_t> scanCommitted(Process& proc, const Pattern& pat, usize maxHits) {
    std::vector<u64> out;
    if (pat.empty()) return out;
    for (const auto& r : proc.committedRanges(true)) {
        if (out.size() >= maxHits) break;
        const usize span = r.end - r.start;
        if (span > 64ull * 1024 * 1024) continue;   // skip gigantic regions
        std::vector<u8> buf(span, 0);
        if (!proc.read(r.start, buf.data(), span)) continue;
        for (usize i = 0; i + pat.length() <= buf.size() && out.size() < maxHits; ++i)
            if (matchAt(buf, i, pat)) out.push_back(r.start + i);
    }
    return out;
}

std::string buildExtendedSignature(Process& proc, const ModuleInfo& mod,
                                   uintptr_t hit, usize mainLength) {
    u8 ext[16] = {};
    if (!proc.read(hit + mainLength, ext, sizeof(ext))) return {};

    bool wild[16] = {};

    // Rule A: any 8-byte window decoding inside the module range -> wildcard
    // window (this catches RIP-relative displacements into module data).
    for (int i = 0; i <= 8; ++i) {
        u64 v = 0;
        for (int b = 0; b < 8 && (i + b) < 16; ++b)
            v |= (u64)ext[i + b] << (8 * b);
        if (v >= mod.base && v < mod.base + mod.size)
            for (int b = 0; b < 8 && (i + b) < 16; ++b) wild[i + b] = true;
    }
    // Rule B: operand bytes after rel32/rel8 control-flow opcodes.
    static const struct { u8 op[3]; u8 opLen; u8 relLen; } rels[] = {
        {{0xE8}, 1, 4}, {{0xE9}, 1, 4}, {{0x74}, 1, 1}, {{0x75}, 1, 1},
        {{0xEB}, 1, 1}, {{0x0F, 0x84}, 2, 4}, {{0x0F, 0x85}, 2, 4},
    };
    for (int i = 0; i < 16; ++i) {
        for (const auto& r : rels) {
            bool m = true;
            for (u8 b = 0; b < r.opLen && m; ++b)
                m = (i + b < 16) && ext[i + b] == r.op[b];
            if (!m) continue;
            for (int b = 0; b < r.relLen; ++b)
                if (i + r.opLen + b < 16) wild[i + r.opLen + b] = true;
        }
    }
    std::string out;
    for (int i = 0; i < 16; ++i) {
        if (i) out += ' ';
        out += wild[i] ? "??" : fmt("%02X", ext[i]);
    }
    return out;
}

uintptr_t resolveSignaturePair(Process& proc, const ModuleInfo& mod,
                               const std::string& mainSig,
                               const std::string& extendedSig) {
    const Pattern main = parseIda(mainSig);
    if (main.empty()) return 0;
    const Pattern ext = parseIda(extendedSig);
    const auto hits = scanModuleAll(proc, mod, main, 64);
    for (const u64 h : hits) {
        if (ext.empty()) return h;                 // no ext stored -> first hit
        u8 bytes[16] = {};
        if (!proc.read(h + main.length(), bytes, sizeof(bytes))) continue;
        bool ok = true;
        for (int i = 0; i < 16 && ok; ++i)
            if (ext.mask[i] && bytes[i] != ext.bytes[i]) ok = false;
        if (ok) return h;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// In-memory PE helpers
// ---------------------------------------------------------------------------
std::vector<PeSection> peSectionsOf(Process& proc, const ModuleInfo& mod) {
    std::vector<PeSection> out;
    u8 hdr[0x1000] = {};
    if (!proc.read(mod.base, hdr, sizeof(hdr))) return out;

    const u32 ntOffset = *(u32*)(hdr + 0x3C);
    if (ntOffset + 0x400 > sizeof(hdr)) return out;
    const u16 numSections = *(u16*)(hdr + ntOffset + 6);
    const u16 optSize = *(u16*)(hdr + ntOffset + 20);
    const u8* secTable = hdr + ntOffset + 24 + optSize;

    for (u16 i = 0; i < numSections && (ntOffset + 24 + optSize + i * 40 + 40) <= sizeof(hdr); ++i) {
        const u8* s = secTable + i * 40;
        char name[9] = {};
        std::memcpy(name, s, 8);
        const u32 vSize = *(u32*)(s + 8);
        const u32 vAddr = *(u32*)(s + 12);
        out.push_back({name, mod.base + vAddr, vSize});
    }
    return out;
}

std::string lookupImportName(Process& proc, const ModuleInfo& mod,
                             uintptr_t iatSlot) {
    u8 hdr[0x1000] = {};
    if (!proc.read(mod.base, hdr, sizeof(hdr))) return {};

    const u32 ntOffset = *(u32*)(hdr + 0x3C);
    // PE32+ data directories start at optional header + 0x70; the import
    // directory is directory[1] -> + 0x78.
    const u8* opt = hdr + ntOffset + 24;
    const u32 impDirRva = *(u32*)(opt + 0x78);
    if (!impDirRva) return {};

    const uintptr_t impDir = mod.base + impDirRva;
    for (u32 i = 0; i < 128; ++i) {
        u8 desc[20] = {};
        if (!proc.read(impDir + i * 20, desc, 20)) break;
        const u32 oftRva = *(u32*)(desc + 0);
        const u32 nameRva = *(u32*)(desc + 12);
        const u32 fthunkRva = *(u32*)(desc + 16);
        if (!fthunkRva) break;   // terminator

        for (u32 t = 0; t < 4096; ++t) {
            const uintptr_t thunkVa = mod.base + fthunkRva + t * 8;
            const u64 fn = proc.read<u64>(thunkVa);
            if (!fn) break;
            if (mod.base + fthunkRva + t * 8 == iatSlot ||
                thunkVa == iatSlot) {
                const std::string dll = proc.readCString(mod.base + nameRva, 64);
                if (!oftRva) return dll;
                const u64 ordName = proc.read<u64>(mod.base + oftRva + t * 8);
                if (ordName & 0x8000000000000000ULL) return dll + "!#" +
                    std::to_string(ordName & 0xFFFF);
                const std::string fnName =
                    proc.readCString(mod.base + (u32)(ordName & 0xFFFFFFFF) + 2, 128);
                return dll + "!" + fnName;
            }
        }
    }
    return {};
}

} // namespace udx
