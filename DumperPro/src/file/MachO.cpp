// ============================================================================
// DumperPro - MachO.cpp
// Portable Mach-O 32/64 + FAT universal binary parser (arama/cikarma tipi:
// "macho" ve "macho-fat"). Sifir harici bagimlilik; sinir-kontrollu okuma.
// ============================================================================
#include "file/MachO.h"
#include "utils/StrUtil.h"
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace dumper {

namespace {

// --- endian-safe okuyucular ------------------------------------------------
// GCC/Clang: __builtin_bswap*; MSVC: _byteswap_* (intrin.h). Tasinabilir sarmalayici.
inline u32 Bswap32(u32 v) {
#if defined(_MSC_VER)
    return _byteswap_ulong(v);
#else
    return __builtin_bswap32(v);
#endif
}
inline u64 Bswap64(u64 v) {
#if defined(_MSC_VER)
    return _byteswap_uint64(v);
#else
    return __builtin_bswap64(v);
#endif
}
u32 Rd32T(const u8* d, bool big) {
    u32 v; memcpy(&v, d, 4);
    if (big) v = Bswap32(v);
    return v;
}
u64 Rd64T(const u8* d, bool big) {
    u64 v; memcpy(&v, d, 8);
    if (big) v = Bswap64(v);
    return v;
}

// --- macho sabitleri -------------------------------------------------------
constexpr u32 MH_MAGIC_    = 0xFEEDFACE;
constexpr u32 MH_CIGAM_    = 0xCEFAEDFE;
constexpr u32 MH_MAGIC_64_ = 0xFEEDFACF;
constexpr u32 MH_CIGAM_64_ = 0xCFFAEDFE;
constexpr u32 FAT_MAGIC_   = 0xCAFEBABE;   // BE degeri; diskte CA FE BA BE
constexpr u32 FAT_MAGIC_64_= 0xCAFEBABF;

constexpr u32 LC_SEGMENT_   = 0x1;
constexpr u32 LC_SYMTAB_    = 0x2;
constexpr u32 LC_UUID_      = 0x1B;
constexpr u32 LC_LOAD_DYLIB_ = 0xC;
constexpr u32 LC_LOAD_WEAK_DYLIB_ = 0x18;              // maskeli: rawCmd 0x80000018
constexpr u32 LC_REEXPORT_DYLIB_  = 0x1F;              // maskeli: rawCmd 0x8000001F
constexpr u32 LC_DYLD_INFO_ = 0x22;
constexpr u32 LC_DYLD_INFO_ONLY_ = 0x22;               // maskeli: rawCmd 0x80000022
constexpr u32 LC_VERSION_MIN_MACOSX_ = 0x24;
constexpr u32 LC_VERSION_MIN_IPHONEOS_ = 0x25;
constexpr u32 LC_SOURCE_VERSION_ = 0x2A;
constexpr u32 LC_MAIN_ = 0x28;                          // maskeli: rawCmd 0x80000028
constexpr u32 LC_SEGMENT_64_ = 0x19;
constexpr u32 LC_BUILD_VERSION_ = 0x32;

std::string CpuName(u32 cputype) {
    switch (cputype & 0x00FFFFFFu) {
        case 7:   return ((cputype & 0x01000000u) ? "x86-64" : "x86");
        case 12:  return ((cputype & 0x01000000u) ? "ARM64" : "ARM");
        case 10:  return "MC680x0";
        case 18:  return "PowerPC";
        case 15:  return "SPARC";
        case 1:   return "VAX";
        default:  return "cpu" + std::to_string(cputype & 0x00FFFFFFu);
    }
}

std::string FileTypeName(u32 ft) {
    switch (ft) {
        case 1: return "OBJECT";
        case 2: return "EXECUTE";
        case 3: return "FVMLIB";
        case 4: return "CORE";
        case 5: return "PRELOAD";
        case 6: return "DYLIB";
        case 7: return "DYLINKER";
        case 8: return "BUNDLE";
        case 9: return "DYLIB_STUB";
        case 10: return "DSYM";
        case 11: return "KEXT_BUNDLE";
        case 12: return "FIXUP_CHAIN";
        default: return "type" + std::to_string(ft);
    }
}

std::string PlatformName(u32 p) {
    switch (p) {
        case 1: return "macOS";
        case 2: return "iOS";
        case 3: return "tvOS";
        case 4: return "watchOS";
        case 5: return "bridgeOS";
        case 6: return "macCatalyst";
        case 7: return "iOS-Simulator";
        case 8: return "tvOS-Simulator";
        case 9: return "watchOS-Simulator";
        case 10: return "DriverKit";
        case 11: return "visionOS";
        case 15: return "iOS-MacCatalyst";
        default: return "platform" + std::to_string(p);
    }
}

std::string ToolName(u32 t) {
    switch (t) {
        case 1: return "clang";
        case 2: return "swift";
        case 3: return "clang++";
        case 4: return "swift++";
        case 5: return "ld";
        default: return "tool" + std::to_string(t);
    }
}

// export trie yuruyusu: her kenar (edge) isim sonekini tasiyor; terminal
// dugumler (termLen > 0) bir export tanimlar. Isim = kokten o dugume kadar
// kenarlarin birlesimi (dyld_export trie ozeti). Visited set ile dongu koruması.
void WalkExportTrie(const u8* d, size_t sz, u64 base, u64 end, size_t depth,
                    const std::string& prefix, std::vector<std::string>& out,
                    std::unordered_set<u64>& visited, u64 trieBase) {
    if (depth > 24 || base >= end || end > sz) return;
    if (!visited.insert(base).second) return;   // ayni dugumu ikinci kez yurume
    size_t p = (size_t)base;
    u64 termLen = 0, shift = 0;
    while (p < end) {
        const u8 b = d[p++];
        termLen |= (u64)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 42) return;
    }
    if (p + termLen > end) return;
    if (termLen > 0 && !prefix.empty() && prefix.size() <= 512 && out.size() < 128) {
        out.push_back(prefix);
    }
    // children
    if (p >= end || p >= sz) return;
    u8 childCount = d[p++];
    for (int i = 0; i < childCount && i < 64; i++) {
        // child: edge string (null-ended) + uleb128 offset
        std::string edge;
        while (p < end && d[p] != 0) {
            const u8 c = d[p];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
                (c >= '0' && c <= '9') || c == '$' || c == '.' || c == ':' ||
                c == '<' || c == '>' || c == ',' || c == '[' || c == ']')
                edge += (char)c;
            p++;
            if (edge.size() > 512) return;
        }
        if (p >= end) return;
        p++;  // null terminator
        u64 childOff = 0;
        shift = 0;
        while (p < end) {
            const u8 b = d[p++];
            childOff |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
            if (shift > 42) return;
        }
        WalkExportTrie(d, sz, trieBase + childOff, end, depth + 1, prefix + edge, out, visited, trieBase);
        if (out.size() >= 128) return;
    }
}

} // namespace

// ---------------------------------------------------------------------------
std::string MachO::PackedVersionStr(u32 v) {
    char b[32];
    snprintf(b, sizeof(b), "%u.%u.%u", (v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF);
    return b;
}

std::string MachO::Sniff(const u8* d, size_t sz) {
    if (!d || sz < 4) return "";
    const u32 m0 = Rd32T(d, false);   // ham big-endian yorumu (fat) veya LE (macho)
    const u32 m1 = Rd32T(d, true);
    if (m0 == MH_MAGIC_ || m0 == MH_MAGIC_64_) return "macho";       // LE yazilisi
    if (m1 == MH_MAGIC_ || m1 == MH_MAGIC_64_) return "macho";       // BE yazilisi
    // FAT: diskte CA FE BA BE -> ham LE okuma 0xBEBAFECA, BE okuma 0xCAFEBABE
    if (m1 == FAT_MAGIC_ || m1 == FAT_MAGIC_64_) return "macho-fat";
    // Java class file ayrimi: CAFEBABE + minor/major plausibility -> macho-fat DEGIL
    return "";
}

bool MachO::Parse(const u8* d, size_t sz, MachOInfo& out) {
    out = MachOInfo();
    const std::string k = Sniff(d, sz);
    if (k == "macho-fat") return ParseFat(d, sz, out);
    if (k != "macho") { out.lastError = "macho magic eslesmedi"; return false; }

    // hangi yazilis?
    const u32 m0 = Rd32T(d, false);
    bool big, is64;
    if (m0 == MH_MAGIC_ || m0 == MH_MAGIC_64_) { big = false; is64 = m0 == MH_MAGIC_64_; }
    else { big = true; is64 = Rd32T(d, true) == MH_MAGIC_64_; }
    return ParseOne(d, sz, out, big, is64, true);
}

bool MachO::ParseFat(const u8* d, size_t sz, MachOInfo& out) {
    out = MachOInfo();
    if (!d || sz < 8) { out.lastError = "fat dosya cok kucuk"; return false; }

    // FAT header BE: magic(4) nfat_arch(4); 64-bit'te her arch 32 bayt (align 8)
    const u32 beMagic = Rd32T(d, true);
    const bool fat64 = beMagic == FAT_MAGIC_64_;
    const u32 n = Rd32T(d + 4, true);
    if (n == 0 || n > 16) { out.lastError = "fat arch sayisi anormal"; return false; }

    out.fat = true;
    out.valid = true;

    size_t bestOff = 0, bestSize = 0;
    for (u32 i = 0; i < n; i++) {
        const size_t ent = 8 + (size_t)i * (fat64 ? 32 : 20);
        if (ent + (fat64 ? 32 : 20) > sz) break;
        MachOFatArch a;
        a.cputype = Rd32T(d + ent, true);
        a.cpusubtype = Rd32T(d + ent + 4, true);
        if (fat64) {
            a.offset = Rd64T(d + ent + 8, true);
            a.size = Rd64T(d + ent + 16, true);
        } else {
            a.offset = Rd32T(d + ent + 8, true);
            a.size = Rd32T(d + ent + 12, true);
        }
        a.cpuName = CpuName(a.cputype);
        if (a.offset + a.size <= sz && a.size > 0) {
            out.fatArchs.push_back(a);
            if (a.size > bestSize) { bestSize = a.size; bestOff = a.offset; }
        }
    }

    // en buyuk arch'i tam parse et
    if (bestOff + bestSize <= sz && bestSize >= 32) {
        MachOInfo sub;
        if (Parse(d + bestOff, (size_t)bestSize, sub)) {
            sub.fat = true;
            sub.fatArchs = out.fatArchs;
            out = std::move(sub);
        }
    }
    return out.valid;
}

bool MachO::ParseOne(const u8* d, size_t sz, MachOInfo& out, bool big, bool is64, bool verboseErrors) {
    const size_t hdrLen = is64 ? 32 : 28;
    if (sz < hdrLen) { out.lastError = "header kisaltir"; return false; }

    out.valid = true;
    out.bits = is64 ? 64 : 32;
    out.endian = big ? "BE" : "LE";

    const u32 cputype = Rd32T(d + 4, big);
    const u32 filetype = Rd32T(d + 12, big);
    const u32 ncmds = Rd32T(d + 16, big);
    const u32 sizeofcmds = Rd32T(d + 20, big);
    out.cpu = CpuName(cputype);
    out.fileType = FileTypeName(filetype);
    out.flags = Rd32T(d + (is64 ? 24 : 20), big);
    out.pie = (out.flags & 0x00200000u) != 0;
    out.loadCmdCount = ncmds;
    if (ncmds == 0 || ncmds > 4096) { out.lastError = "ncmds anormal"; return out.valid; }
    if ((size_t)sizeofcmds + hdrLen > sz) { out.lastError = "sizeofcmds tasmasi"; return out.valid; }

    // load commands
    size_t p = hdrLen;
    const size_t end = hdrLen + sizeofcmds;
    for (u32 i = 0; i < ncmds && p + 8 <= end; i++) {
        const u32 cmd = Rd32T(d + p, big) & 0x3FFFFFFFu;
        const u32 rawCmd = Rd32T(d + p, big);
        const u32 cmdsize = Rd32T(d + p + 4, big);
        if (cmdsize < 8 || p + cmdsize > sz) break;

        if (cmd == LC_SEGMENT_ || cmd == LC_SEGMENT_64_) {
            out.segmentCount++;
            const bool seg64 = cmd == LC_SEGMENT_64_;
            const size_t nsectsOff = p + (seg64 ? 72 : 56);
            u32 nsects = Rd32T(d + p + (seg64 ? 64 : 48), big);
            if (nsects > 96) nsects = 96;
            for (u32 s = 0; s < nsects; s++) {
                const size_t so = nsectsOff + (size_t)s * (seg64 ? 80 : 68);
                if (so + (seg64 ? 80 : 68) > sz) break;
                MachOSection sec;
                sec.name.assign((const char*)(d + so), 16);
                sec.segment.assign((const char*)(d + so + 16), 16);
                sec.name.resize(strnlen(sec.name.c_str(), 16));
                sec.segment.resize(strnlen(sec.segment.c_str(), 16));
                if (seg64) {
                    sec.addr = Rd64T(d + so + 32, big);
                    sec.size = Rd64T(d + so + 40, big);
                    sec.offset = Rd32T(d + so + 48, big);
                    sec.flags = Rd32T(d + so + 64, big);
                } else {
                    sec.addr = Rd32T(d + so + 32, big);
                    sec.size = Rd32T(d + so + 36, big);
                    sec.offset = Rd32T(d + so + 40, big);
                    sec.flags = Rd32T(d + so + 56, big);
                }
                // SECTION_TYPE = flags & 0xFF; S_ATTR_* high bits
                sec.exec = (sec.flags & 0x400u) != 0 || (sec.flags & 0x00000400u) != 0;
                sec.write = (sec.flags & 0x00000080u) != 0;   // S_ZEROFILL / attr yoksa seg'e bak
                if (sec.segment.rfind("__TEXT", 0) == 0) { sec.exec = true; sec.write = false; }
                if (sec.segment.rfind("__DATA", 0) == 0) { sec.write = true; sec.exec = false; }
                out.sections.push_back(std::move(sec));
                if (out.sections.size() >= 96) break;
            }
        } else if (cmd == LC_UUID_) {
            if (p + 24 <= sz) {
                char b[40];
                const u8* u = d + p + 8;
                snprintf(b, sizeof(b), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                         u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                         u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                out.uuid = b;
            }
        } else if (cmd == LC_MAIN_) {
            if (p + 16 <= sz) out.entryPoint = Rd64T(d + p + 8, big);
        } else if (cmd == LC_SYMTAB_) {
            if (p + 24 <= sz) {
                out.symtabCount = Rd32T(d + p + 12, big);   // nsyms
            }
        } else if (cmd == LC_DYLD_INFO_ || cmd == LC_DYLD_INFO_ONLY_) {
            // dyld_info_command: cmd(0) size(4) rebase(8,12) bind(16,20) weak(24,28)
            //                    lazy(32,36) export_off(40) export_size(44)
            if (p + 48 <= sz) {
                out.exportOff = Rd32T(d + p + 40, big);
                out.exportSize = Rd32T(d + p + 44, big);
                if (out.exportOff && out.exportSize) {
                    std::unordered_set<u64> visited;
                    WalkExportTrie(d, sz, out.exportOff, (u64)out.exportOff + out.exportSize, 0, "",
                                   out.exports, visited, out.exportOff);
                }
            }
        } else if (cmd == LC_BUILD_VERSION_) {
            if (p + 24 <= sz) {
                const u32 plat = Rd32T(d + p + 8, big);
                const u32 minos = Rd32T(d + p + 12, big);
                const u32 sdk = Rd32T(d + p + 16, big);
                out.platform = PlatformName(plat);
                out.minos = PackedVersionStr(minos);
                out.sdk = PackedVersionStr(sdk);
                // tool listesi
                const u32 ntools = Rd32T(d + p + 20, big);
                size_t tp = p + 24;
                for (u32 t = 0; t < ntools && t < 8 && tp + 8 <= sz; t++, tp += 8) {
                    const u32 tn = Rd32T(d + tp, big);
                    const u32 tv = Rd32T(d + tp + 4, big);
                    out.linkedLibs.push_back("(build) " + ToolName(tn) + " " + PackedVersionStr(tv));
                }
            }
        } else if (cmd == LC_VERSION_MIN_MACOSX_ || cmd == LC_VERSION_MIN_IPHONEOS_) {
            if (p + 16 <= sz) {
                const u32 ver = Rd32T(d + p + 8, big);
                out.minos = PackedVersionStr(ver);
                out.platform = cmd == LC_VERSION_MIN_MACOSX_ ? "macOS" : "iOS";
            }
        } else if (cmd == LC_SOURCE_VERSION_) {
            if (p + 24 <= sz) {
                const u64 sv = Rd64T(d + p + 8, big);
                char b[40];
                snprintf(b, sizeof(b), "%u.%u.%u.%u.%u",
                         (u32)((sv >> 40) & 0xFFFFFFu), (u32)((sv >> 30) & 0x3FFu),
                         (u32)((sv >> 20) & 0x3FFu), (u32)((sv >> 10) & 0x3FFu), (u32)(sv & 0x3FFu));
                out.sourceVersion = b;
            }
        } else if (rawCmd == LC_LOAD_DYLIB_ || rawCmd == LC_LOAD_WEAK_DYLIB_ || rawCmd == LC_REEXPORT_DYLIB_) {
            if (p + 24 <= sz) {
                const u32 nameOff = Rd32T(d + p + 8, big);
                if (nameOff && p + nameOff < sz) {
                    const char* q = (const char*)(d + p + nameOff);
                    std::string lib;
                    lib.assign(q, strnlen(q, std::min<size_t>(cmdsize > nameOff ? cmdsize - nameOff : 64, 256)));
                    if (!lib.empty() && out.linkedLibs.size() < 48)
                        out.linkedLibs.push_back(std::move(lib));
                }
            }
        }
        p += cmdsize;
    }
    return out.valid;
}

} // namespace dumper
