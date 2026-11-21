// ============================================================================
// DumperPro - BinFold.cpp
//
// Port of trumank/binfold core (MIT, (c) 2025 Truman Kilen) - see BinFold.h
// for the algorithm mapping and adaptation notes. Pure C++20, zero external
// dependencies (SHA-1 and UUIDv5 are implemented inline below).
//
// Pipeline (mirrors upstream lib.rs analyze + match_with_database):
//   1. discover functions           (pe.rs .pdata | elf.rs symtab |
//                                    sweep.rs call-target sweep for raw/x86)
//   2. mask relocatable bytes       (arch/x86.rs BlockMasker, decoder-free)
//   3. masked body -> function GUID (warp.rs compute_warp_uuid, UuidV5)
//   4. derive constraints           (child_call / parent_call)
//   5. exact GUID seed matches, then iterative constraint propagation until
//      fixpoint                     (lib.rs match_with_database loop)
//   6. similarity scoring + inserted/deleted classification
// ============================================================================
#include "binfold/BinFold.h"

#include <cstring>
#include <array>     // Guid = std::array<u8,16> (MSVC C2027: tam tanim icin sart)
#include <utility>   // std::pair / std::move

namespace dumper {
namespace binfold {

namespace {

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-1) - required by RFC 4122 UUIDv5. Compact implementation.
// ---------------------------------------------------------------------------
struct Sha1 {
    u32 h[5];
    u64 totalLen = 0;
    u8 buf[64];
    size_t bufLen = 0;

    Sha1() {
        h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE;
        h[3] = 0x10325476; h[4] = 0xC3D2E1F0;
    }
    static u32 Rol(u32 v, int s) { return (v << s) | (v >> (32 - s)); }

    void Block(const u8* p) {
        u32 w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (u32)p[i*4] << 24 | (u32)p[i*4+1] << 16 | (u32)p[i*4+2] << 8 | (u32)p[i*4+3];
        for (int i = 16; i < 80; i++)
            w[i] = Rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            u32 f, k;
            if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
            u32 t = Rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = Rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    void Update(const u8* data, size_t len) {
        totalLen += len;
        while (len) {
            if (bufLen == 0 && len >= 64) { Block(data); data += 64; len -= 64; continue; }
            size_t take = std::min(len, (size_t)64 - bufLen);
            memcpy(buf + bufLen, data, take);
            bufLen += take; data += take; len -= take;
            if (bufLen == 64) { Block(buf); bufLen = 0; }
        }
    }

    // 20-byte digest into out
    void Final(u8 out[20]) {
        const u64 bits = totalLen * 8;
        u8 pad = 0x80;
        Update(&pad, 1);
        u8 z = 0;
        while (bufLen != 56) Update(&z, 1);
        u8 lenb[8];
        for (int i = 0; i < 8; i++) lenb[i] = (u8)(bits >> (56 - i * 8));
        Update(lenb, 8);
        for (int i = 0; i < 5; i++) {
            out[i*4]   = (u8)(h[i] >> 24);
            out[i*4+1] = (u8)(h[i] >> 16);
            out[i*4+2] = (u8)(h[i] >> 8);
            out[i*4+3] = (u8)(h[i]);
        }
    }
};

// ---------------------------------------------------------------------------
// UUIDv5 (RFC 4122) with binfold's domain scheme (hash.rs):
//   key(domain) = UuidV5(ROOT_NS, domain_name)
//   guid        = UuidV5(key, bytes)
// ROOT_NS = c1a7f83a-38a2-4bed-b6a3-babc0df6860f (binfold hash.rs UUIDV5_ROOT)
// ---------------------------------------------------------------------------
using Guid = std::array<u8, 16>;

struct GuidHash {
    size_t operator()(const Guid& g) const {
        u64 h = 1469598103934665603ull;
        for (u8 b : g) { h ^= b; h *= 1099511628211ull; }
        return (size_t)h;
    }
};

Guid ParseUuid(const char* hex36) {
    Guid g{};
    int bi = 0;
    for (const char* p = hex36; *p && bi < 16; p++) {
        if (*p == '-') continue;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        g[bi++] = (u8)(nib(p[0]) * 16 + nib(p[1]));
        p++;
    }
    return g;
}

bool ParseGuidStr(const std::string& s, Guid& out) {
    u8 b[16];
    int hi = 0;
    for (char c : s) {
        if (c == '-') continue;
        int v = (c >= '0' && c <= '9') ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (v < 0 || hi >= 32) return false;
        if (hi % 2 == 0) b[hi / 2] = (u8)(v << 4);
        else             b[hi / 2] |= (u8)v;
        hi++;
    }
    if (hi != 32) return false;
    memcpy(out.data(), b, 16);
    return true;
}

Guid UuidV5(const Guid& ns, const u8* data, size_t len) {
    Sha1 s;
    s.Update(ns.data(), 16);
    if (len) s.Update(data, len);
    u8 d[20];
    s.Final(d);
    Guid out{};
    memcpy(out.data(), d, 16);
    out[6] = (u8)((out[6] & 0x0F) | 0x50);   // version 5
    out[8] = (u8)((out[8] & 0x3F) | 0x80);   // variant 10xx
    return out;
}

const Guid& DomainKey(const char* domain) {
    static const Guid kRoot       = ParseUuid("c1a7f83a-38a2-4bed-b6a3-babc0df6860f");
    static const Guid kFunction   = UuidV5(kRoot, (const u8*)"function", 8);
    static const Guid kBasicBlock = UuidV5(kRoot, (const u8*)"basic_block", 11);
    static const Guid kChildCall  = UuidV5(kRoot, (const u8*)"child_call", 10);
    static const Guid kParentCall = UuidV5(kRoot, (const u8*)"parent_call", 11);
    if (strcmp(domain, "function") == 0) return kFunction;
    if (strcmp(domain, "basic_block") == 0) return kBasicBlock;
    if (strcmp(domain, "child_call") == 0) return kChildCall;
    return kParentCall;
}

Guid HashDomain(const char* domain, const u8* data, size_t len) {
    return UuidV5(DomainKey(domain), data, len);
}

std::string GuidStr(const Guid& g) {
    char buf[40];
    snprintf(buf, sizeof(buf),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7],
             g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    return buf;
}

// ---------------------------------------------------------------------------
// Minimal PE parse (raw file image; self-contained so the module stays
// pluggable - no dependency on core/PEFile.h)
// ---------------------------------------------------------------------------
struct PeSec {
    u32 va = 0, vsize = 0, rawOff = 0, rawSize = 0;
    u32 chars = 0;   // section characteristics
    bool exec = false;
};

struct PeInfo {
    bool ok = false;
    u32 machine = 0;
    u32 sizeImage = 0;
    PeSec secs[96];
    u32 secCount = 0;
    u32 ddRva[16] = {0}, ddSize[16] = {0};

    u32 RvaToOff(u32 rva) const {
        for (u32 i = 0; i < secCount; i++) {
            const PeSec& s = secs[i];
            const u32 vspan = s.vsize ? s.vsize : s.rawSize;
            if (rva >= s.va && rva < s.va + vspan) {
                const u32 delta = rva - s.va;
                if (delta >= s.rawSize) return 0xFFFFFFFFu;  // virtual-only tail
                return s.rawOff + delta;
            }
        }
        return 0xFFFFFFFFu;
    }
};

u16 Rd16(const u8* p) { u16 v; memcpy(&v, p, 2); return v; }
u32 Rd32(const u8* p) { u32 v; memcpy(&v, p, 4); return v; }
u64 Rd64(const u8* p) { u64 v; memcpy(&v, p, 8); return v; }

bool ParsePe(const u8* d, size_t n, PeInfo& out) {
    if (n < 0x40 || d[0] != 'M' || d[1] != 'Z') return false;
    const u32 eLfanew = Rd32(d + 0x3C);
    if (eLfanew + 24 > n) return false;
    const u8* pe = d + eLfanew;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] != 0 || pe[3] != 0) return false;
    out.machine = Rd16(pe + 4);
    const u16 numSec = Rd16(pe + 6);
    const u16 optSize = Rd16(pe + 20);
    if (numSec > 96) return false;
    const u8* opt = pe + 24;
    if (eLfanew + 24 + optSize > n || optSize < 2) return false;
    const u16 magic = Rd16(opt);
    const bool plus = (magic == 0x20B);
    if (!plus && magic != 0x10B) return false;

    if (optSize >= 60) out.sizeImage = Rd32(opt + 56);
    const u32 ddBase = plus ? 112 : 96;
    if (optSize >= ddBase + 16 * 8) {
        for (int i = 0; i < 16; i++) {
            out.ddRva[i]  = Rd32(opt + ddBase + i * 8);
            out.ddSize[i] = Rd32(opt + ddBase + i * 8 + 4);
        }
    }

    const u8* sec = opt + optSize;
    if ((size_t)(sec - d) + (size_t)numSec * 40 > n) return false;
    out.secCount = numSec;
    for (u16 i = 0; i < numSec; i++) {
        const u8* s = sec + i * 40;
        out.secs[i].vsize   = Rd32(s + 8);
        out.secs[i].va      = Rd32(s + 12);
        out.secs[i].rawSize = Rd32(s + 16);
        out.secs[i].rawOff  = Rd32(s + 20);
        out.secs[i].chars   = Rd32(s + 36);
        out.secs[i].exec    = (out.secs[i].chars & 0x20000000u) != 0;  // IMAGE_SCN_MEM_EXECUTE
    }
    out.ok = true;
    return true;
}

// ---------------------------------------------------------------------------
// Minimal ELF64 parse (LSB). Functions come from .symtab (preferred) or
// .dynsym; PT_LOAD program headers give vaddr -> file offset mapping.
// ---------------------------------------------------------------------------
struct ElfInfo {
    bool ok = false;
    struct Sym { u64 value, size; };
    std::vector<Sym> funcs;
    struct Load { u64 vaddr, filesz, offset; bool exec; };
    std::vector<Load> loads;

    u64 VaToOff(u64 va) const {
        for (const Load& l : loads)
            if (va >= l.vaddr && va < l.vaddr + l.filesz) return l.offset + (va - l.vaddr);
        return ~0ull;
    }
    bool ExecAt(u64 va) const {
        for (const Load& l : loads)
            if (l.exec && va >= l.vaddr && va < l.vaddr + l.filesz) return true;
        return false;
    }
};

bool ParseElf64(const u8* d, size_t n, ElfInfo& out) {
    if (n < 64 || memcmp(d, "\x7f" "ELF", 4) != 0) return false;
    if (d[4] != 2 /*ELFCLASS64*/ || d[5] != 1 /*LSB*/) return false;
    const u64 shoff = Rd64(d + 0x28);
    const u16 shentsize = Rd16(d + 0x3A);
    const u16 shnum = Rd16(d + 0x3C);
    const u64 phoff = Rd64(d + 0x20);
    const u16 phentsize = Rd16(d + 0x36);
    const u16 phnum = Rd16(d + 0x38);

    for (u16 i = 0; phnum && phentsize >= 56 && i < phnum; i++) {
        const u64 po = phoff + (u64)i * phentsize;
        if (po + 56 > n) return false;
        if (Rd32(d + po) != 1 /*PT_LOAD*/) continue;
        ElfInfo::Load l;
        l.offset = Rd64(d + po + 8);
        l.vaddr  = Rd64(d + po + 16);
        l.filesz = Rd64(d + po + 32);
        l.exec   = (Rd32(d + po + 4) & 1) != 0;   // PF_X
        if (l.offset + l.filesz > n) l.filesz = n - l.offset;
        out.loads.push_back(l);
    }

    // section headers: find SHT_SYMTAB (2), fall back to SHT_DYNSYM (11)
    u64 symShOff = 0;
    bool haveSym = false;
    for (u16 i = 0; shnum && shentsize >= 64 && i < shnum; i++) {
        const u64 so = shoff + (u64)i * shentsize;
        if (so + 64 > n) return false;
        const u32 shType = Rd32(d + so + 4);
        if (shType == 2) { symShOff = so; haveSym = true; break; }
        if (shType == 11 && !haveSym) { symShOff = so; haveSym = true; }  // keep looking for symtab
    }
    if (haveSym) {
        const u64 symOff = Rd64(d + symShOff + 24), symSize = Rd64(d + symShOff + 32);
        const u32 symLink = Rd32(d + symShOff + 40);
        u64 strOff = 0, strSize = 0;
        if (symLink < shnum) {
            const u64 sto = shoff + (u64)symLink * shentsize;
            if (sto + 64 <= n) {
                strOff  = Rd64(d + sto + 24);
                strSize = Rd64(d + sto + 32);
            }
        }
        if (symOff + symSize <= n && strOff + strSize <= n && strSize) {
            // Elf64_Sym: name u32, info u8, other u8, shndx u16, value u64, size u64
            const size_t symCount = symSize / 24;
            for (size_t i = 0; i < symCount; i++) {
                const u8* s = d + symOff + i * 24;
                if (s + 24 > d + n) break;
                if ((s[4] & 0xF) != 2 /*STT_FUNC*/) continue;
                const u16 shndx = Rd16(s + 6);
                const u64 value = Rd64(s + 8);
                const u64 size  = Rd64(s + 16);
                if (!value || !size || shndx == 0) continue;
                // bound check against the section carrying the function code
                u64 maxEnd = 0;
                for (u16 k = 0; k < shnum; k++) {
                    const u64 so2 = shoff + (u64)k * shentsize;
                    if (so2 + 64 > n) break;
                    const u64 secAddr = Rd64(d + so2 + 16);   // sh_addr
                    const u64 secSize = Rd64(d + so2 + 32);   // sh_size
                    if (value >= secAddr && value < secAddr + secSize) {
                        maxEnd = std::min<u64>(secAddr + secSize, value + size);
                        break;
                    }
                }
                const u64 len = maxEnd ? maxEnd - value : size;
                if (len) out.funcs.push_back({value, len});
            }
        }
    }
    out.ok = true;
    return true;
}

// ---------------------------------------------------------------------------
// Address space: functions and call targets live in "image-relative" space
// (PE: RVA, ELF: vaddr, raw: file offset). Body bytes are read through the
// mapping; call targets are computed in the same space so the call graph and
// function index stay consistent.
// ---------------------------------------------------------------------------
struct AddrSpace {
    enum Kind { Raw, PeRva, ElfVa } kind = Raw;
    const PeInfo* pe = nullptr;
    const ElfInfo* elf = nullptr;
    size_t fileSize = 0;
    u64 span = 0;   // address-space span (SizeOfImage / file size)

    u64 ToOff(u64 addr) const {
        if (kind == Raw) return addr < span ? addr : ~0ull;
        if (kind == PeRva) return pe->RvaToOff((u32)addr);
        return elf->VaToOff(addr);
    }

    // Validate a ToOff result. PE uses the u32 sentinel 0xFFFFFFFF (which is
    // NOT ~0ull when widened to u64) - compare both, plus the file bounds.
    bool ValidOff(u64 off) const {
        return off != ~0ull && off != 0xFFFFFFFFull && off < fileSize;
    }
};

// ---------------------------------------------------------------------------
// Function container used by the diff engine
// ---------------------------------------------------------------------------
struct FuncCtx {
    u64 addr = 0;
    u32 size = 0;
    Guid guid{};
    std::vector<u32> callees, callers;   // indices into the same function list
    std::set<Guid> constraints;          // child_call + parent_call guids
};

// WARP masking, decoder-free approximation (see BinFold.h): zero the rel32
// displacement of direct call/jmp (E8/E9) and the rel8 of short jmp (EB).
void MaskBody(const u8* body, size_t len, std::vector<u8>& out) {
    out.assign(body, body + len);
    size_t i = 0;
    while (i < len) {
        const u8 b = out[i];
        if ((b == 0xE8 || b == 0xE9) && i + 5 <= len) { memset(&out[i + 1], 0, 4); i += 5; }
        else if (b == 0xEB && i + 2 <= len) { out[i + 1] = 0; i += 2; }
        else i++;
    }
}

// two-level WARP hash: fixed 64-byte segments -> basic_block GUIDs -> concat
// -> function GUID (upstream hashes actual disassembled basic blocks)
Guid FuncGuid(const u8* masked, size_t len) {
    constexpr size_t kBlock = 64;
    std::vector<u8> concat;
    concat.reserve(((len + kBlock - 1) / kBlock + 1) * 16);
    for (size_t off = 0; off < len; off += kBlock) {
        Guid bg = HashDomain("basic_block", masked + off, std::min(kBlock, len - off));
        concat.insert(concat.end(), bg.begin(), bg.end());
    }
    if (concat.empty()) return HashDomain("function", nullptr, 0);
    return HashDomain("function", concat.data(), concat.size());
}

// direct call (E8 rel32) targets in address space
void CollectCalls(const u8* body, size_t len, u64 funcAddr, std::vector<u64>& targets) {
    size_t i = 0;
    while (i + 5 <= len) {
        if (body[i] == 0xE8) {
            i32 rel;
            memcpy(&rel, body + i + 1, 4);
            targets.push_back(funcAddr + (u64)i + 5 + (u64)(i64)rel);
            i += 5;
        } else {
            i++;
        }
    }
}

// ---------------------------------------------------------------------------
// Content-defined chunking (Gear rolling hash) for a decoder-independent byte
// similarity score. Deterministic table: identical for both inputs.
// ---------------------------------------------------------------------------
struct GearChunker {
    u64 table[256];
    GearChunker() {
        u64 x = 0x9E3779B97F4A7C15ull;   // fixed seed -> cross-run determinism
        for (int i = 0; i < 256; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            table[i] = x;
        }
    }
    static u64 Fnv(const u8* p, size_t n) {
        u64 h = 1469598103934665603ull;
        for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
        return h;
    }
    // chunk the buffer, accumulate (hash -> total bytes); ~1 KiB average chunk
    // (10-bit mask): small chunks keep 20-50 byte edits from poisoning 4 KiB
    // regions while staying memory-cheap even on 1 GiB inputs
    void Chunks(const u8* data, size_t len, std::unordered_map<u64, u64>& lenByHash) const {
        const size_t kMin = 128, kMax = 8192;
        size_t start = 0;
        u64 h = 0;
        for (size_t i = 0; i < len; i++) {
            h = (h << 1) + table[data[i]];
            const size_t cl = i + 1 - start;
            if (((h & 0x3FF) == 0 && cl >= kMin) || cl >= kMax || i + 1 == len) {
                lenByHash[Fnv(data + start, cl)] += cl;
                start = i + 1;
                h = 0;
            }
        }
    }
};

double ByteSimilarity(const u8* a, size_t sa, const u8* b, size_t sb) {
    if (!sa || !sb) return 0.0;
    static const GearChunker gear;
    std::unordered_map<u64, u64> ma, mb;
    gear.Chunks(a, sa, ma);
    gear.Chunks(b, sb, mb);
    u64 common = 0;
    for (const auto& kv : ma) {
        auto it = mb.find(kv.first);
        if (it != mb.end()) common += std::min(kv.second, it->second);
    }
    return 2.0 * (double)common / ((double)sa + (double)sb);
}

} // namespace

// ---------------------------------------------------------------------------
// Function discovery
// ---------------------------------------------------------------------------
static const size_t kMaxFile = 1ull << 30;        // 1 GiB, same cap as HexTool
static const size_t kMaxFunctions = 2000000;

bool BinFold::LoadFile(const fs::path& path, std::vector<u8>& data, std::string& err) {
    std::error_code ec;
    const u64 fsz = fs::file_size(path, ec);
    if (ec) { err = "cannot stat: " + path.string(); return false; }
    if (fsz > kMaxFile) { err = "file too large (cap 1 GiB): " + path.string(); return false; }
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) { err = "cannot open: " + path.string(); return false; }
    data.resize((size_t)fsz);
    if (fsz && !in.read((char*)data.data(), (std::streamsize)fsz)) {
        err = "short read: " + path.string();
        return false;
    }
    return true;
}

bool BinFold::Analyze(const u8* data, size_t size, std::vector<BfFunction>& out,
                      std::string& format, std::string& err) {
    if (!data || !size) { err = "empty input"; return false; }
    format.clear();
    out.clear();

    struct Range { u64 addr, end; };   // address-space span of one function
    std::vector<Range> funcsRaw;
    AddrSpace sp;
    sp.fileSize = size;
    sp.span = size;

    PeInfo pe;
    ElfInfo elf;
    const bool isPe = ParsePe(data, size, pe);
    const bool isElf = !isPe && ParseElf64(data, size, elf);

    if (isPe) {
        sp.kind = AddrSpace::PeRva;
        sp.pe = &pe;
        sp.span = pe.sizeImage ? pe.sizeImage : size;
        auto machineLabel = [&]() -> std::string {
            switch (pe.machine) {
                case 0x8664: return "x64";
                case 0x014C: return "x86";
                case 0xAA64: return "ARM64";
                default: {
                    char mb[16];
                    snprintf(mb, sizeof(mb), "0x%04X", pe.machine);
                    return mb;
                }
            }
        };

        // x64 PE: .pdata exception directory gives exact function bounds
        bool usedPdata = false;
        if (pe.machine == 0x8664 && pe.ddSize[3] >= 12) {
            const u32 pdOff = pe.RvaToOff(pe.ddRva[3]);
            if (pdOff != 0xFFFFFFFFu) {
                const u32 count = pe.ddSize[3] / 12;
                for (u32 i = 0; i < count; i++) {
                    const size_t eo = (size_t)pdOff + i * 12;
                    if (eo + 12 > size) break;
                    const u32 begin = Rd32(data + eo), end = Rd32(data + eo + 4);
                    if (begin >= end || end > sp.span) continue;
                    if (end - begin > (16u << 20)) continue;   // sanity cap
                    funcsRaw.push_back({begin, end});
                }
                if (!funcsRaw.empty()) {
                    usedPdata = true;
                    format = "PE " + machineLabel() + " (.pdata, " +
                             std::to_string(funcsRaw.size()) + " entries)";
                }
            }
        }
        if (!usedPdata) {
            // x86 PE / ARM64 PE / missing .pdata: E8 sweep over exec sections
            u32 swept = 0;
            for (u32 pass = 0; pass < 2 && !swept; pass++) {
                for (u32 i = 0; i < pe.secCount; i++) {
                    const PeSec& s = pe.secs[i];
                    if (pass == 0 && !s.exec) continue;            // pass 1: exec only
                    u32 span = s.vsize ? s.vsize : s.rawSize;
                    if (span > s.rawSize) span = s.rawSize;        // file-backed bytes only
                    const u32 off = pe.RvaToOff(s.va);
                    if (off == 0xFFFFFFFFu || !span) continue;
                    if ((u64)off + span > size) span = (u32)(size - off);
                    for (u32 p = 0; p + 5 <= span; p++) {
                        if (data[off + p] != 0xE8) continue;
                        i32 rel; memcpy(&rel, data + off + p + 1, 4);
                        const u64 target = (u64)s.va + p + 5 + (u64)(i64)rel;
                        if (target >= sp.span) continue;
                        funcsRaw.push_back({target, 0});
                        swept++;
                    }
                }
            }
            format = "PE " + machineLabel() + " (call-sweep)";
        }
    } else if (isElf) {
        sp.kind = AddrSpace::ElfVa;
        sp.elf = &elf;
        for (const ElfInfo::Load& l : elf.loads)
            sp.span = std::max<u64>(sp.span, l.vaddr + l.filesz);
        for (const ElfInfo::Sym& s : elf.funcs) {
            const u64 off = elf.VaToOff(s.value);
            if (off == ~0ull || off >= size) continue;
            u64 len = s.size;
            if (off + len > size) len = size - off;
            if (!len) continue;
            funcsRaw.push_back({s.value, s.value + len});
        }
        if (!funcsRaw.empty()) {
            format = "ELF64 (symtab, " + std::to_string(funcsRaw.size()) + " funcs)";
        } else {
            // stripped or non-x86 ELF: E8 sweep over executable PT_LOADs
            // (works for x86/x64 .so only; AArch64 needs real disassembly)
            for (const ElfInfo::Load& l : elf.loads) {
                if (!l.exec) continue;
                for (u64 p = 0; p + 5 <= l.filesz; p++) {
                    if (data[l.offset + p] != 0xE8) continue;
                    i32 rel; memcpy(&rel, data + l.offset + p + 1, 4);
                    const u64 target = l.vaddr + p + 5 + (u64)(i64)rel;
                    if (target >= sp.span) continue;
                    funcsRaw.push_back({target, 0});
                }
            }
            format = "ELF64 (call-sweep, " + std::to_string(funcsRaw.size()) + " funcs)";
        }
    } else {
        // raw binary: E8 rel32 sweep over the whole buffer (file-offset space)
        for (size_t p = 0; p + 5 <= size; p++) {
            if (data[p] != 0xE8) continue;
            i32 rel; memcpy(&rel, data + p + 1, 4);
            const u64 target = p + 5 + (u64)(i64)rel;
            if (target >= size) continue;
            funcsRaw.push_back({target, 0});
        }
        format = "raw (x86 call-sweep)";
    }

    if (funcsRaw.empty()) {
        format += "; 0 functions (data-only or unsupported arch)";
        return true;   // valid result: nothing to fingerprint
    }

    // sort + dedup entry points
    std::sort(funcsRaw.begin(), funcsRaw.end(),
              [](const Range& a, const Range& b) { return a.addr < b.addr; });
    funcsRaw.erase(std::unique(funcsRaw.begin(), funcsRaw.end(),
                     [](const Range& a, const Range& b) { return a.addr == b.addr; }),
                   funcsRaw.end());
    if (funcsRaw.size() > kMaxFunctions) funcsRaw.resize(kMaxFunctions);

    // resolve sizes: .pdata/symtab entries carry ends; sweep entries end at the
    // next entry point (classic call-sweep approximation)
    for (size_t i = 0; i < funcsRaw.size(); i++) {
        Range& f = funcsRaw[i];
        if (f.end == 0 || f.end <= f.addr)
            f.end = (i + 1 < funcsRaw.size()) ? funcsRaw[i + 1].addr : sp.span;
        if (f.end > sp.span) f.end = sp.span;
        if (f.end <= f.addr) f.end = f.addr + 1;
    }

    // hash bodies (read through the address-space mapping)
    out.reserve(funcsRaw.size());
    std::vector<u8> masked;
    for (const Range& f : funcsRaw) {
        const u64 off = sp.ToOff(f.addr);
        if (!sp.ValidOff(off)) continue;
        u64 len = f.end - f.addr;
        if (off + len > size) len = size - off;
        if (!len) continue;
        MaskBody(data + off, (size_t)len, masked);
        BfFunction bf;
        bf.addr = f.addr;
        bf.size = (u32)len;
        bf.guid = GuidStr(FuncGuid(masked.data(), masked.size()));
        out.push_back(std::move(bf));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Diff + iterative constraint matching (binfold lib.rs match_with_database,
// adapted: the reference binary plays the role of the symbol database)
// ---------------------------------------------------------------------------
bool BinFold::Diff(const u8* a, size_t sa, const u8* b, size_t sb,
                   BfDiffResult& out, std::string& err) {
    out = BfDiffResult{};
    std::vector<BfFunction> fa, fb;
    if (!Analyze(a, sa, fa, out.formatA, err)) return false;
    if (!Analyze(b, sb, fb, out.formatB, err)) return false;
    out.funcsA = fa;
    out.funcsB = fb;
    // byte similarity over RELOC-MASKED buffers (E8/E9/EB displacements zeroed):
    // consistent with the WARP philosophy - relocations are noise for code
    // comparison, otherwise relinked-but-identical code scores ~0
    {
        std::vector<u8> mab, mbb;
        MaskBody(a, sa, mab);
        MaskBody(b, sb, mbb);
        out.simBytes = ByteSimilarity(mab.data(), mab.size(), mbb.data(), mbb.size());
    }

    if (fa.empty() || fb.empty()) {
        out.inserted = fb;
        out.deleted = fa;
        return true;   // nothing matchable (stripped / data-only input)
    }

    // ---- internal richer view ----
    std::vector<FuncCtx> A(fa.size()), B(fb.size());
    std::unordered_map<u64, u32> idxA, idxB;    // addr -> index (address space)
    for (size_t i = 0; i < fa.size(); i++) {
        A[i].addr = fa[i].addr; A[i].size = fa[i].size;
        ParseGuidStr(fa[i].guid, A[i].guid);
        idxA[fa[i].addr] = (u32)i;
    }
    for (size_t i = 0; i < fb.size(); i++) {
        B[i].addr = fb[i].addr; B[i].size = fb[i].size;
        ParseGuidStr(fb[i].guid, B[i].guid);
        idxB[fb[i].addr] = (u32)i;
    }

    // call graphs (E8 rel32 within each binary's own address space)
    auto buildCalls = [&](std::vector<FuncCtx>& v, const std::unordered_map<u64, u32>& idx,
                          const u8* data, size_t size, const AddrSpace& sp) {
        for (size_t i = 0; i < v.size(); i++) {
            FuncCtx& f = v[i];
            const u64 off = sp.ToOff(f.addr);
            if (!sp.ValidOff(off) || off + f.size > size) continue;
            std::vector<u64> targets;
            CollectCalls(data + off, f.size, f.addr, targets);
            for (u64 t : targets) {
                auto it = idx.find(t);
                if (it != idx.end() && it->second != i) {
                    f.callees.push_back(it->second);
                    v[it->second].callers.push_back((u32)i);
                }
            }
        }
    };
    // call graphs (E8 rel32 within each binary's own address space);
    // address spaces re-derived here (Analyze already validated the containers)
    PeInfo pa, pb;
    ElfInfo ea, eb;
    AddrSpace spA, spB;
    spA.kind = AddrSpace::Raw; spA.fileSize = sa; spA.span = sa;
    spB.kind = AddrSpace::Raw; spB.fileSize = sb; spB.span = sb;
    if (ParsePe(a, sa, pa)) {
        spA.kind = AddrSpace::PeRva; spA.pe = &pa;
        spA.span = pa.sizeImage ? pa.sizeImage : sa;
    } else if (ParseElf64(a, sa, ea)) {
        spA.kind = AddrSpace::ElfVa; spA.elf = &ea;
        for (const ElfInfo::Load& l : ea.loads) spA.span = std::max<u64>(spA.span, l.vaddr + l.filesz);
        if (!spA.span) spA.span = sa;
    }
    if (ParsePe(b, sb, pb)) {
        spB.kind = AddrSpace::PeRva; spB.pe = &pb;
        spB.span = pb.sizeImage ? pb.sizeImage : sb;
    } else if (ParseElf64(b, sb, eb)) {
        spB.kind = AddrSpace::ElfVa; spB.elf = &eb;
        for (const ElfInfo::Load& l : eb.loads) spB.span = std::max<u64>(spB.span, l.vaddr + l.filesz);
        if (!spB.span) spB.span = sb;
    }
    buildCalls(A, idxA, a, sa, spA);
    buildCalls(B, idxB, b, sb, spB);

    // constraint sets: child_call(callee guid) + parent_call(caller guid)
    auto buildCons = [](std::vector<FuncCtx>& v) {
        for (FuncCtx& f : v) {
            for (u32 c : f.callees) f.constraints.insert(HashDomain("child_call", v[c].guid.data(), 16));
            for (u32 p : f.callers) f.constraints.insert(HashDomain("parent_call", v[p].guid.data(), 16));
        }
    };
    buildCons(A);
    buildCons(B);

    // constraint index for A (guid -> candidate functions)
    std::unordered_map<Guid, std::vector<u32>, GuidHash> indexA;
    for (size_t i = 0; i < A.size(); i++)
        for (const Guid& g : A[i].constraints) indexA[g].push_back((u32)i);

    // ---- exact GUID seed matches (same masked body => same function) ----
    std::unordered_map<Guid, std::vector<u32>, GuidHash> freeA;
    for (size_t i = 0; i < A.size(); i++) freeA[A[i].guid].push_back((u32)i);
    std::vector<std::optional<std::pair<u32, bool>>> matchB(B.size());   // (A index, exact)
    std::vector<bool> usedA(A.size(), false);

    for (size_t j = 0; j < B.size(); j++) {
        auto it = freeA.find(B[j].guid);
        if (it == freeA.end() || it->second.empty()) continue;
        const u32 ai = it->second.front();
        it->second.erase(it->second.begin());
        matchB[j] = {ai, true};
        usedA[ai] = true;
        out.exactCount++;
    }

    // ---- binfold's iterative loop: constraints from matched neighbours ----
    bool progress = true;
    while (progress) {
        progress = false;
        for (size_t j = 0; j < B.size(); j++) {
            if (matchB[j]) continue;
            // constraint guids derived from GUID-equal (matched) neighbours are
            // shared across the two binaries - the engine analogue of binfold's
            // symbol-name constraints
            std::set<Guid> cons;
            for (u32 c : B[j].callees)
                if (matchB[c]) cons.insert(HashDomain("child_call", B[c].guid.data(), 16));
            for (u32 p : B[j].callers)
                if (matchB[p]) cons.insert(HashDomain("parent_call", B[p].guid.data(), 16));
            if (cons.empty()) continue;

            // score candidate A functions by shared constraints
            std::unordered_map<u32, u32> score;
            for (const Guid& g : cons) {
                auto it = indexA.find(g);
                if (it == indexA.end()) continue;
                for (u32 ai : it->second) score[ai]++;
            }
            u32 best = ~0u, bestScore = 0, ties = 0;
            for (const auto& kv : score) {
                if (usedA[kv.first]) continue;
                if (kv.second > bestScore) { bestScore = kv.second; best = kv.first; ties = 1; }
                else if (kv.second == bestScore) ties++;
            }
            if (best == ~0u || bestScore < 2 || ties > 1) continue;   // need one unique confident candidate

            matchB[j] = {best, false};
            usedA[best] = true;
            out.inferredCount++;
            progress = true;
        }
    }

    // ---- results ----
    double matchedBytes = 0, totalBytes = 0;
    for (const FuncCtx& f : A) totalBytes += f.size;
    for (const FuncCtx& f : B) totalBytes += f.size;
    for (size_t j = 0; j < B.size(); j++) {
        if (!matchB[j]) { out.inserted.push_back(fb[j]); continue; }
        const u32 ai = matchB[j]->first;
        BfMatch m;
        m.addrA = A[ai].addr;
        m.addrB = B[j].addr;
        m.sizeA = A[ai].size;
        m.sizeB = B[j].size;
        m.exact = matchB[j]->second;
        if (m.exact) {
            m.confidence = 1.0;
        } else {
            u32 total = (u32)B[j].constraints.size();
            u32 hit = 0;
            for (const Guid& g : B[j].constraints)
                if (A[ai].constraints.count(g)) hit++;
            m.confidence = total ? (double)hit / (double)total : 0.0;
        }
        matchedBytes += std::min((double)m.sizeA, (double)m.sizeB);
        out.matches.push_back(m);
    }
    for (size_t i = 0; i < A.size(); i++)
        if (!usedA[i]) out.deleted.push_back(fa[i]);

    out.simFunctions = totalBytes > 0 ? 2.0 * matchedBytes / totalBytes : -1.0;
    std::sort(out.matches.begin(), out.matches.end(),
              [](const BfMatch& x, const BfMatch& y) { return x.addrB < y.addrB; });
    return true;
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------
static std::string Pct(double v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f%%", v * 100.0);
    return buf;
}

std::string BinFold::BuildReport(const BfDiffResult& r,
                                 const std::string& nameA, const std::string& nameB) {
    std::string L;
    auto line = [&](const std::string& s) { L += s; L += '\n'; };
    auto hdr = [&](const std::string& t) { line("---- " + t + " ----"); };
    char buf[256];

    line("");
    line("BINFOLD DIFF REPORT");
    line("File A (reference): " + nameA + "  [" + r.formatA + "]");
    line("File B (target)   : " + nameB + "  [" + r.formatB + "]");
    line("");
    hdr("functions");
    snprintf(buf, sizeof(buf), "Functions A : %zu", r.funcsA.size()); line(buf);
    snprintf(buf, sizeof(buf), "Functions B : %zu", r.funcsB.size()); line(buf);
    snprintf(buf, sizeof(buf), "Exact match : %zu  (identical WARP GUID)", r.exactCount); line(buf);
    snprintf(buf, sizeof(buf), "Inferred    : %zu  (constraint propagation)", r.inferredCount); line(buf);
    snprintf(buf, sizeof(buf), "Inserted    : %zu  (only in B)", r.inserted.size()); line(buf);
    snprintf(buf, sizeof(buf), "Deleted     : %zu  (only in A)", r.deleted.size()); line(buf);
    if (r.simFunctions >= 0) {
        snprintf(buf, sizeof(buf), "Similarity  : %s (function bodies) / %s (bytes, CDC, reloc-masked)",
                 Pct(r.simFunctions).c_str(), Pct(r.simBytes).c_str());
        line(buf);
    } else {
        snprintf(buf, sizeof(buf), "Similarity  : %s (bytes, CDC, reloc-masked; no functions on one side)",
                 Pct(r.simBytes).c_str());
        line(buf);
    }

    // top changed matched pairs: inferred matches + body size deltas
    if (!r.matches.empty()) {
        std::vector<const BfMatch*> ch;
        for (const BfMatch& m : r.matches)
            if (!m.exact || m.sizeA != m.sizeB) ch.push_back(&m);
        std::sort(ch.begin(), ch.end(), [](const BfMatch* x, const BfMatch* y) {
            const u32 dx = x->sizeA > x->sizeB ? x->sizeA - x->sizeB : x->sizeB - x->sizeA;
            const u32 dy = y->sizeA > y->sizeB ? y->sizeA - y->sizeB : y->sizeB - y->sizeA;
            if (dx != dy) return dx > dy;
            return x->addrB < y->addrB;
        });
        line("");
        hdr("top changed/modified pairs (max 10)");
        size_t n = 0;
        for (const BfMatch* m : ch) {
            if (++n > 10) break;
            char tail[32] = "";
            if (!m->exact) snprintf(tail, sizeof(tail), "  conf %s", Pct(m->confidence).c_str());
            snprintf(buf, sizeof(buf), "  0x%llX -> 0x%llX  size %u -> %u  %s%s",
                     (unsigned long long)m->addrA, (unsigned long long)m->addrB,
                     m->sizeA, m->sizeB, m->exact ? "exact" : "inferred", tail);
            line(buf);
        }
        if (!n) line("  (no size deltas)");
    }

    // matched symbol-style entries: address + GUID per pair (first 20) -
    // the analogue of binfold's matched-name listing
    if (!r.matches.empty()) {
        std::unordered_map<u64, const char*> guidByAddr;
        for (const BfFunction& f : r.funcsA) guidByAddr.emplace(f.addr, f.guid.c_str());
        line("");
        hdr("first matched entries (max 20)");
        for (size_t i = 0; i < r.matches.size() && i < 20; i++) {
            const BfMatch& m = r.matches[i];
            auto it = guidByAddr.find(m.addrA);
            const char* g = it != guidByAddr.end() ? it->second : "";
            snprintf(buf, sizeof(buf), "  sub_%04llX -> sub_%04llX  %s  %s",
                     (unsigned long long)m.addrA, (unsigned long long)m.addrB,
                     m.exact ? "exact   " : "inferred", g);
            line(buf);
        }
        if (r.matches.size() > 20)
            line("  ... (" + std::to_string(r.matches.size() - 20) + " more, see --bindiff-json)");
    }

    auto topList = [&](const std::vector<BfFunction>& v, const char* title) {
        if (v.empty()) return;
        std::vector<const BfFunction*> s;
        for (const BfFunction& f : v) s.push_back(&f);
        std::sort(s.begin(), s.end(),
                  [](const BfFunction* x, const BfFunction* y) { return x->size > y->size; });
        line("");
        hdr(title);
        for (size_t i = 0; i < s.size() && i < 5; i++) {
            snprintf(buf, sizeof(buf), "  0x%llX  (%u bytes, guid %s...)",
                     (unsigned long long)s[i]->addr, s[i]->size, s[i]->guid.substr(0, 8).c_str());
            line(buf);
        }
    };
    topList(r.inserted, "top inserted (max 5)");
    topList(r.deleted, "top deleted (max 5)");

    line("");
    const double sim = r.simFunctions >= 0 ? r.simFunctions : r.simBytes;
    snprintf(buf, sizeof(buf),
             "Summary: similarity %s | matched %zu/%zu (exact %zu, inferred %zu) | inserted %zu | deleted %zu",
             Pct(sim).c_str(),
             r.exactCount + r.inferredCount, r.funcsB.size(),
             r.exactCount, r.inferredCount, r.inserted.size(), r.deleted.size());
    line(buf);
    return L;
}

static std::string JsonEsc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((u8)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
                else o += c;
        }
    }
    return o;
}

std::string BinFold::BuildJson(const BfDiffResult& r,
                               const std::string& nameA, const std::string& nameB) {
    std::ostringstream o;
    o << "{\n";
    o << "  \"fileA\": \"" << JsonEsc(nameA) << "\",\n";
    o << "  \"fileB\": \"" << JsonEsc(nameB) << "\",\n";
    o << "  \"formatA\": \"" << JsonEsc(r.formatA) << "\",\n";
    o << "  \"formatB\": \"" << JsonEsc(r.formatB) << "\",\n";
    o << "  \"similarity\": {\"functions\": " << (r.simFunctions >= 0 ? r.simFunctions : -1.0)
      << ", \"bytes_cdc\": " << r.simBytes << "},\n";
    o << "  \"counts\": {"
      << "\"functionsA\": " << r.funcsA.size()
      << ", \"functionsB\": " << r.funcsB.size()
      << ", \"exact\": " << r.exactCount
      << ", \"inferred\": " << r.inferredCount
      << ", \"inserted\": " << r.inserted.size()
      << ", \"deleted\": " << r.deleted.size() << "},\n";

    o << "  \"matches\": [\n";
    for (size_t i = 0; i < r.matches.size(); i++) {
        const BfMatch& m = r.matches[i];
        o << "    {\"a\": \"0x" << std::hex << m.addrA << std::dec
          << "\", \"b\": \"0x" << std::hex << m.addrB << std::dec
          << "\", \"sizeA\": " << m.sizeA << ", \"sizeB\": " << m.sizeB
          << ", \"kind\": \"" << (m.exact ? "exact" : "inferred") << "\""
          << ", \"confidence\": " << m.confidence << "}"
          << (i + 1 < r.matches.size() ? "," : "") << "\n";
    }
    o << "  ],\n";

    auto arr = [&](const char* key, const std::vector<BfFunction>& v, bool last) {
        o << "  \"" << key << "\": [\n";
        for (size_t i = 0; i < v.size(); i++) {
            o << "    {\"addr\": \"0x" << std::hex << v[i].addr << std::dec
              << "\", \"size\": " << v[i].size
              << ", \"guid\": \"" << v[i].guid << "\"}"
              << (i + 1 < v.size() ? "," : "") << "\n";
        }
        o << "  ]" << (last ? "\n" : ",\n");
    };
    arr("inserted", r.inserted, false);
    arr("deleted", r.deleted, true);
    o << "}\n";
    return o.str();
}

} // namespace binfold
} // namespace dumper
