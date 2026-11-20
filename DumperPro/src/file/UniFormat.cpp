// ============================================================================
// DumperPro - UniFormat.cpp
// ELF + DEX parsing, UE version-string scanning, magic sniffing.
// Tamamen portable: tum okumalar sinir kontrollu, bozuk dosyalarda
// kismi sonuc + invalid=false doner, crash olmaz.
// ============================================================================

#include "file/UniFormat.h"
#include "file/MachO.h"

namespace dumper {

namespace {

u16 Rd16LE(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
u32 Rd32LE(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
u64 Rd64LE(const u8* p) { return (u64)Rd32LE(p) | ((u64)Rd32LE(p + 4) << 32); }
u16 Rd16BE(const u8* p) { return (u16)((p[0] << 8) | p[1]); }
u32 Rd32BE(const u8* p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3]; }
u64 Rd64BE(const u8* p) { return (u64)Rd32BE(p) << 32 | Rd32BE(p + 4); }

std::string MachineName(u32 m) {
    switch (m) {
        case 0x03: return "x86";
        case 0x08: return "MIPS";
        case 0x14: return "PowerPC";
        case 0x28: return "ARM";
        case 0x3E: return "x86-64";
        case 0xB7: return "AArch64";
        case 0xF3: return "RISC-V";
        default:   return Hex32(m);
    }
}

std::string ElfTypeName(u16 t) {
    switch (t) {
        case 1: return "REL";
        case 2: return "EXEC";
        case 3: return "DYN";
        case 4: return "CORE";
        default: return Hex32(t);
    }
}

std::string ShTypeName(u32 t) {
    switch (t) {
        case 0: return "NULL";
        case 1: return "PROGBITS";
        case 2: return "SYMTAB";
        case 3: return "STRTAB";
        case 4: return "RELA";
        case 5: return "HASH";
        case 6: return "DYNAMIC";
        case 7: return "NOTE";
        case 8: return "NOBITS";
        case 9: return "REL";
        case 11: return "DYNSYM";
        case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY";
        default: return Hex32(t);
    }
}

// safe C-string copy from buffer
std::string SafeCStr(const u8* d, size_t sz, size_t off, size_t cap = 128) {
    if (off >= sz) return "";
    size_t end = off;
    while (end < sz && d[end] != 0 && end - off < cap) end++;
    return std::string((const char*)d + off, end - off);
}

// MUTF-8 (DEX) -> UTF-8 best-effort. 0xC0 0x80 -> NUL; uc baytlik surrogate
// ciftleri birlestirilir; gecersiz baytlar atlanir.
bool DecodeMutf8(const u8* d, size_t sz, size_t off, size_t utf16Units,
                 size_t* outEnd, std::string& out) {
    out.clear();
    size_t p = off;
    size_t units = 0;
    u32 pendingSurrogate = 0;
    auto Emit = [&](u32 cp) {
        if (cp >= 0xD800 && cp <= 0xDBFF) { pendingSurrogate = cp; return; }
        if (cp >= 0xDC00 && cp <= 0xDFFF && pendingSurrogate) {
            cp = 0x10000 + ((pendingSurrogate - 0xD800) << 10) + (cp - 0xDC00);
            pendingSurrogate = 0;
        }
        if (cp == 0) { out += '\0'; units++; return; }
        char b[4];
        int n = 0;
        if (cp < 0x80) { b[n++] = (char)cp; }
        else if (cp < 0x800) { b[n++] = (char)(0xC0 | (cp >> 6)); b[n++] = (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { b[n++] = (char)(0xE0 | (cp >> 12)); b[n++] = (char)(0x80 | ((cp >> 6) & 0x3F)); b[n++] = (char)(0x80 | (cp & 0x3F)); }
        else { b[n++] = (char)(0xF0 | (cp >> 18)); b[n++] = (char)(0x80 | ((cp >> 12) & 0x3F)); b[n++] = (char)(0x80 | ((cp >> 6) & 0x3F)); b[n++] = (char)(0x80 | (cp & 0x3F)); }
        out.append(b, (size_t)n);
        units++;
    };
    while (p < sz && units < utf16Units) {
        const u8 c = d[p];
        if (c == 0) { p++; break; }                     // string_data_item sonlandiricisi
        if (c == 0xC0 && p + 1 < sz && d[p + 1] == 0x80) { Emit(0); p += 2; continue; }
        if (c < 0x80) { Emit(c); p += 1; }
        else if ((c & 0xE0) == 0xC0 && p + 1 < sz) {
            const u8 c2 = d[p + 1];
            if ((c2 & 0xC0) == 0x80) { Emit(((c & 0x1F) << 6) | (c2 & 0x3F)); p += 2; }
            else { p++; break; }
        } else if ((c & 0xF0) == 0xE0 && p + 2 < sz) {
            const u8 c2 = d[p + 1], c3 = d[p + 2];
            if ((c2 & 0xC0) == 0x80 && (c3 & 0xC0) == 0x80) {
                Emit(((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F)); p += 3;
            } else { p++; break; }
        } else { p++; break; }
    }
    if (outEnd) *outEnd = p;
    return !out.empty();
}

} // namespace

// ---------------------------------------------------------------------------
bool UniFormat::ParseElf(const u8* d, size_t sz, ElfInfo& out) {
    out = ElfInfo{};
    if (!d || sz < 52 || memcmp(d, "\x7f" "ELF", 4) != 0) return false;

    const u8 eiClass = d[4];   // 1=32, 2=64
    const u8 eiData  = d[5];   // 1=LE, 2=BE
    if (eiClass != 1 && eiClass != 2) return false;
    if (eiData != 1 && eiData != 2) return false;

    out.bits = eiClass == 2 ? 64 : 32;
    out.endian = eiData == 2 ? "BE" : "LE";
    out.valid = true;

    auto Rd16 = eiData == 2 ? Rd16BE : Rd16LE;
    auto Rd32 = eiData == 2 ? Rd32BE : Rd32LE;
    auto Rd64 = eiData == 2 ? Rd64BE : Rd64LE;

    const u16 eType = Rd16(d + 16);
    const u16 eMachine = Rd16(d + 18);
    out.type = ElfTypeName(eType);
    out.machine = MachineName(eMachine);
    out.entryPoint = out.bits == 64 ? Rd64(d + 24) : Rd32(d + 24);
    out.sectionCount = Rd16(d + (out.bits == 64 ? 0x3C : 0x30)); // e_shnum

    if (out.sectionCount == 0) return true; // stripped section table

    const u64 shOff = out.bits == 64 ? Rd64(d + 0x28) : Rd32(d + 0x20);
    const u16 shEntSize = Rd16(d + (out.bits == 64 ? 0x3A : 0x2E));
    const u16 shStrNdx = Rd16(d + (out.bits == 64 ? 0x3E : 0x32));
    if (shOff == 0 || shEntSize == 0) return true;

    // section header string table
    u64 shstrOff = 0, shstrSize = 0;
    if (shStrNdx < out.sectionCount) {
        const u64 shBase = shOff + (u64)shStrNdx * shEntSize;
        if (shBase + shEntSize <= sz) {
            const u8* sh = d + shBase;
            shstrOff = out.bits == 64 ? Rd64(sh + 0x18) : Rd32(sh + 0x10);
            shstrSize = out.bits == 64 ? Rd64(sh + 0x20) : Rd32(sh + 0x14);
        }
    }

    const u32 cap = std::min<u32>(out.sectionCount, 64);
    for (u32 i = 0; i < cap; i++) {
        const u64 shBase = shOff + (u64)i * shEntSize;
        if (shBase + shEntSize > sz) break;
        const u8* sh = d + shBase;
        ElfSection s;
        const u32 nameOff = Rd32(sh + 0x00);
        s.typeName = ShTypeName(Rd32(sh + 0x04));
        if (out.bits == 64) {
            s.flags  = Rd32(sh + 0x08);
            s.addr   = Rd64(sh + 0x10);
            s.offset = Rd64(sh + 0x18);
            s.size   = Rd64(sh + 0x20);
        } else {
            s.flags  = Rd32(sh + 0x0C);
            s.addr   = Rd32(sh + 0x14);
            s.offset = Rd32(sh + 0x18);
            s.size   = Rd32(sh + 0x20);
        }
        s.exec  = (s.flags & 0x4u) != 0;   // SHF_EXECINSTR
        s.write = (s.flags & 0x1u) != 0;   // SHF_WRITE
        s.alloc = (s.flags & 0x2u) != 0;   // SHF_ALLOC
        if (nameOff < shstrSize && shstrOff + nameOff < sz)
            s.name = SafeCStr(d, sz, shstrOff + nameOff);
        out.sections.push_back(std::move(s));
    }
    return true;
}

// ---------------------------------------------------------------------------
bool UniFormat::ParseDex(const u8* d, size_t sz, DexInfo& out) {
    out = DexInfo{};
    if (!d || sz < 0x70) return false;
    if (memcmp(d, "dex\n", 4) != 0) return false;
    out.valid = true;
    out.version = std::string((const char*)d + 4, 3);
    auto Rd32 = [d](size_t off) -> u32 { return Rd32LE(d + off); };
    out.stringIdsSize  = Rd32(0x38);
    out.typeIdsSize    = Rd32(0x40);
    out.protoIdsSize   = Rd32(0x48);
    out.fieldIdsSize   = Rd32(0x50);
    out.methodIdsSize  = Rd32(0x58);
    out.classDefsSize  = Rd32(0x60);
    return true;
}

// ---------------------------------------------------------------------------
std::vector<UeVersionHit> UniFormat::UeVersionStrings(const u8* d, size_t sz, size_t cap) {
    std::vector<UeVersionHit> hits;
    if (!d || sz < 8) return hits;
    const char needle[] = "++UE";
    const size_t nlen = 4;

    for (size_t i = 0; i + nlen <= sz && hits.size() < cap; i++) {
        if (memcmp(d + i, needle, nlen) != 0) continue;
        // parse: ++UE4+Release-4.27.2-0.0  (++UE5+Main olabilir)
        const size_t maxTok = 64;
        std::string tok((const char*)d + i, std::min(maxTok, sz - i));
        // tok'u gecerli karakterler disinda kes
        size_t t = 0;
        while (t < tok.size() && (isalnum((u8)tok[t]) || tok[t] == '+' || tok[t] == '-' || tok[t] == '.')) t++;
        tok = tok.substr(0, t);
        if (tok.size() < 10) continue;

        UeVersionHit h;
        h.raw = tok;
        const size_t rel = tok.find("Release-");
        if (rel != std::string::npos) {
            std::string v = tok.substr(rel + 8);
            h.version = v;
        } else if (tok.find("+Main") != std::string::npos) {
            h.version = "Main (custom build)";
        } else {
            continue; // tam eslesme yok
        }
        hits.push_back(std::move(h));
        i += tok.size() - 1;
    }
    return hits;
}

// ---------------------------------------------------------------------------
// YENI: ELF dynamic symbol tablosu (.dynsym + .dynstr)
// ---------------------------------------------------------------------------
u32 UniFormat::ParseElfDynSym(const u8* d, size_t sz, const ElfInfo& elf,
                              std::vector<ElfDynSym>& out, size_t cap) {
    out.clear();
    if (!d || sz < 16 || !elf.valid) return 0;

    // DYNSYM bolumunu bul (ParseElf zaten SHT_DYNSYM etiketli)
    const ElfSection* symSec = nullptr;
    const ElfSection* strSec = nullptr;
    for (const ElfSection& s : elf.sections) {
        if (s.typeName == "DYNSYM") { symSec = &s; break; }
    }
    if (!symSec) return 0;

    // sh_link yerine STRTAB arama: .dynstr veya DYNSYM'in hemen ardindaki STRTAB
    u64 strOff = 0, strSize = 0;
    for (const ElfSection& s : elf.sections) {
        if (s.typeName == "STRTAB") {
            if (s.name == ".dynstr" || s.name == ".dstr") { strSec = &s; break; }
            // yedek: dynsym offsetine yakin olan strtab
            if (!strSec && s.offset >= symSec->offset &&
                s.offset < symSec->offset + symSec->size + 0x100) strSec = &s;
        }
    }
    if (strSec) { strOff = strSec->offset; strSize = strSec->size; }

    const bool is64 = elf.bits == 64;
    const size_t ent = is64 ? 24 : 16;
    u64 symOff = symSec->offset;
    u64 symSize = symSec->size;
    if (symOff == 0 || symSize < ent) return 0;
    if (symOff + symSize > sz) symSize = sz > symOff ? sz - symOff : 0;

    const u32 total = (u32)(symSize / ent);
    const u32 capN = std::min<u32>(total, 65536);
    for (u32 i = 0; i < capN; i++) {
        const u8* e = d + symOff + (size_t)i * ent;
        u32 stName; u32 stInfo; u64 stValue; u64 stSize;
        if (is64) {
            stName = Rd32LE(e);
            stInfo = e[4];
            stValue = Rd64LE(e + 8);
            stSize = Rd64LE(e + 16);
        } else {
            stName = Rd32LE(e);
            stValue = Rd32LE(e + 4);
            stSize = Rd32LE(e + 8);
            stInfo = e[12];
        }
        const u32 bind = stInfo >> 4;
        const u32 type = stInfo & 0xF;
        // sadece disa aktarilanlar: GLOBAL(1)/WEAK(2) + FUNC(2)/OBJECT(1), value != 0
        if (bind != 1 && bind != 2) continue;
        if (type != 1 && type != 2) continue;
        if (!stValue) continue;

        ElfDynSym s;
        s.bind = bind == 1 ? "GLOBAL" : "WEAK";
        s.type = type == 2 ? "FUNC" : "OBJECT";
        s.value = stValue;
        s.size = stSize;
        if (stName && strOff + stName < sz && stName < strSize)
            s.name = SafeCStr(d, sz, strOff + stName, 256);
        if (out.size() < cap) out.push_back(std::move(s));
        else return total;
    }
    return total;
}

// ---------------------------------------------------------------------------
// YENI: DEX string havuzu (string_data_item, MUTF-8)
// ---------------------------------------------------------------------------
bool UniFormat::ParseDexStrings(const u8* d, size_t sz, DexStrings& out,
                                size_t sampleCap, size_t scanCap) {
    out = DexStrings{};
    if (!d || sz < 0x70 || memcmp(d, "dex\n", 4) != 0) return false;

    const u32 idsSize = Rd32LE(d + 0x38);
    const u32 idsOff  = Rd32LE(d + 0x3C);
    if (!idsSize || !idsOff || idsOff >= sz) return false;
    out.totalStrings = idsSize;

    const u32 n = std::min<u32>(idsSize, (u32)scanCap);
    auto AddHint = [&](const std::string& s) {
        if (out.hints.size() >= 32) return;
        bool dup = false;
        for (const std::string& h : out.hints) if (h == s) { dup = true; break; }
        if (!dup) out.hints.push_back(s);
    };

    for (u32 i = 0; i < n; i++) {
        const u64 idOff = idsOff + (u64)i * 4;
        if (idOff + 4 > sz) break;
        const u32 dataOff = Rd32LE(d + idOff);
        if (!dataOff || dataOff >= sz) continue;
        // uleb128 utf16_size
        size_t p = dataOff;
        u64 units = 0; int shift = 0;
        while (p < sz && shift <= 28) {
            const u8 b = d[p++];
            units |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        if (units == 0 || units > 8192) continue;
        std::string decoded;
        size_t endP = 0;
        if (!DecodeMutf8(d, sz, p, (size_t)units, &endP, decoded)) continue;
        out.decoded++;
        if (out.sample.size() < sampleCap && !decoded.empty() && decoded.size() >= 4)
            out.sample.push_back(decoded);
        // ipuclari: paket/motor stringleri (Lcom/xxx/yyy; veya com.xxx.yyy)
        if (!decoded.empty()) {
            std::string low = decoded;
            for (char& c : low) c = (char)tolower((u8)c);
            if (low.rfind("lcom/", 0) == 0 || low.rfind("com.", 0) == 0) AddHint(decoded);
            else if (low.find("unity") != std::string::npos || low.find("unreal") != std::string::npos ||
                     low.find("epicgames") != std::string::npos || low.find("il2cpp") != std::string::npos ||
                     low.find("tencent") != std::string::npos || low.find("supercell") != std::string::npos ||
                     low.find("godot") != std::string::npos)
                AddHint(decoded);
        }
    }
    return out.decoded > 0;
}

// ---------------------------------------------------------------------------
std::string UniFormat::SniffMagic(const u8* d, size_t sz) {
    if (!d || sz < 4) return "unknown";
    if (d[0] == 'M' && d[1] == 'Z') return "pe";
    if (d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F') return "elf";
    if (memcmp(d, "dex\n", 4) == 0) return "dex";
    if (d[0] == 'P' && d[1] == 'K') return "zip";
    if (d[0] == 'a' && d[1] == 'r' && d[2] == 't' && d[3] == '\n') return "oat";
    if (memcmp(d, "vdex", 4) == 0) return "vdex";
    if (memcmp(d, "cdex", 4) == 0) return "cdex";
    // YENI: Mach-O + FAT universal binary (Java class CAFEBABE ayrimi dahil)
    {
        const std::string m = MachO::Sniff(d, sz);
        if (!m.empty()) return m;   // "macho" | "macho-fat"
    }
    // IL2CPP metadata: sanity 0xFAB11BAF (LE: AF 1B B1 FA) + makul surum
    if (sz >= 8 && d[0] == 0xAF && d[1] == 0x1B && d[2] == 0xB1 && d[3] == 0xFA) {
        const i32 ver = (i32)((u32)d[4] | ((u32)d[5] << 8) | ((u32)d[6] << 16) | ((u32)d[7] << 24));
        if (ver >= 16 && ver <= 31) return "il2cpp";
    }
    return "unknown";
}

} // namespace dumper
