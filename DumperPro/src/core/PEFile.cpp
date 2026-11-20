#include "core/PEFile.h"
#include "utils/StrUtil.h"

#include <cmath>

namespace dumper {

namespace {

inline u16 Rd16(const u8* d, size_t off) {
    if (!d) return 0;
    u16 v; memcpy(&v, d + off, 2); return v;
}
inline u32 Rd32(const u8* d, size_t off) {
    if (!d) return 0;
    u32 v; memcpy(&v, d + off, 4); return v;
}
inline u64 Rd64(const u8* d, size_t off) {
    if (!d) return 0;
    u64 v; memcpy(&v, d + off, 8); return v;
}

// portable memmem replacement
inline const void* MemFind(const void* haystack, size_t hayLen, const void* needle, size_t needleLen) {
    if (!haystack || !needle || needleLen == 0 || hayLen < needleLen) return nullptr;
    const u8* h = (const u8*)haystack;
    const u8* n = (const u8*)needle;
    for (size_t i = 0; i + needleLen <= hayLen; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needleLen) == 0) return h + i;
    }
    return nullptr;
}

constexpr u32 kMaxSections = 96;

} // namespace

bool PEFile::IsPE(const u8* data, size_t size) {
    if (!data || size < 0x40) return false;
    if (Rd16(data, 0) != 0x5A4D) return false; // "MZ"
    u32 peOff = Rd32(data, 0x3C);
    if (peOff + 0x18 > size) return false;
    return Rd32(data, peOff) == 0x00004550;    // "PE\0\0"
}

bool PEFile::Parse(const u8* data, size_t size, bool isMapped) {
    valid_ = false;
    d_ = data;
    sz_ = size;
    mapped_ = isMapped;
    secs_.clear();

    if (!IsPE(data, size)) return false;

    u32 peOff = Rd32(data, 0x3C);
    if (peOff + 0x100 > size) return false;

    machine_ = Rd16(data, peOff + 4);
    u16 numSections = Rd16(data, peOff + 6);
    u16 optSize = Rd16(data, peOff + 20);

    bool pe32plus = Rd16(data, peOff + 24) == 0x20B;
    if (!pe32plus) return false; // x64 only

    // Optional header (PE32+): ImageBase at +24, SizeOfImage at +56
    u32 optOff = peOff + 24;
    imgBase_     = Rd64(data, optOff + 24);
    sizeImage_   = Rd32(data, optOff + 56);
    sizeHeaders_ = Rd32(data, optOff + 60);

    // data directories (PE32+): base at optOff + 112
    exportDirRva_  = Rd32(data, optOff + 112);
    exportDirSize_ = Rd32(data, optOff + 116);
    for (int i = 0; i < 16; i++) {
        dataDirsRva_[i]  = Rd32(data, optOff + 112 + i * 8);
        dataDirsSize_[i] = Rd32(data, optOff + 112 + i * 8 + 4);
    }

    u32 secTable = optOff + optSize;
    if (numSections > kMaxSections) numSections = kMaxSections;
    if ((size_t)secTable + numSections * 40 > size) return false;

    for (u16 i = 0; i < numSections; i++) {
        const u8* s = data + secTable + (size_t)i * 40;
        PESection sec;
        char name[9] = {0};
        memcpy(name, s, 8);
        sec.name    = name;
        sec.vs      = Rd32(s, 8);
        sec.va      = Rd32(s, 12);
        sec.rawSize = Rd32(s, 16);
        sec.rawOff  = Rd32(s, 20);
        sec.chars   = Rd32(s, 36);
        sec.exec  = (sec.chars & 0x20000000) != 0;
        sec.read  = (sec.chars & 0x40000000) != 0;
        sec.write = (sec.chars & 0x80000000) != 0;
        secs_.push_back(sec);
    }
    valid_ = true;
    return true;
}

u32 PEFile::RvaToOffset(u32 rva) const {
    if (mapped_) return rva;
    if (rva < sizeHeaders_) return rva;
    for (const PESection& s : secs_) {
        if (rva >= s.va && rva < s.va + std::max(s.vs, s.rawSize)) {
            u32 delta = rva - s.va;
            if (delta < s.rawSize) return s.rawOff + delta;
            return 0xFFFFFFFFu; // in virtual zone (bss / zero fill)
        }
    }
    return 0xFFFFFFFFu;
}

const PESection* PEFile::SectionAtRva(u32 rva) const {
    for (const PESection& s : secs_) {
        if (rva >= s.va && rva < s.va + std::max(s.vs, (u32)1)) return &s;
    }
    return nullptr;
}

const PESection* PEFile::SectionByName(const std::string& lowerName) const {
    for (const PESection& s : secs_) {
        if (str::Lower(s.name) == lowerName) return &s;
    }
    return nullptr;
}

std::vector<ExportEntry> PEFile::Exports() const {
    std::vector<ExportEntry> out;
    if (!valid_ || !exportDirRva_) return out;

    u32 off = RvaToOffset(exportDirRva_);
    if (off == 0xFFFFFFFFu || off + 0x28 > sz_) return out;

    u32 numFunctions = Rd32(d_, off + 0x14);
    u32 numNames     = Rd32(d_, off + 0x18);
    u32 addrNames    = RvaToOffset(Rd32(d_, off + 0x20));
    u32 addrFuncs    = RvaToOffset(Rd32(d_, off + 0x1C));
    u32 addrOrds     = RvaToOffset(Rd32(d_, off + 0x24));
    if (numNames > 0x100000) numNames = 0x100000;

    for (u32 i = 0; i < numNames; i++) {
        if (addrNames + (size_t)i * 4 + 4 > sz_) break;
        u32 nameRva = Rd32(d_, addrNames + (size_t)i * 4);
        u32 nameOff = RvaToOffset(nameRva);
        if (nameOff == 0xFFFFFFFFu || nameOff >= sz_) continue;
        ExportEntry e;
        const char* p = (const char*)(d_ + nameOff);
        size_t maxlen = sz_ - nameOff;
        e.name.assign(p, strnlen(p, std::min<size_t>(maxlen, 256)));
        if (addrOrds + (size_t)i * 2 + 2 <= sz_) {
            u16 ordIdx = Rd16(d_, addrOrds + (size_t)i * 2);
            if (addrFuncs + (size_t)ordIdx * 4 + 4 <= sz_) e.rva = Rd32(d_, addrFuncs + (size_t)ordIdx * 4);
        }
        e.ord = i;
        out.push_back(std::move(e));
    }
    (void)numFunctions;
    return out;
}

std::vector<std::string> PEFile::VersionStrings() const {
    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    if (!valid_ || !d_) return out;

    const char* needles[] = { "++UE4+Release-", "++UE5+Release-", "Release-4.", "Release-5." };
    for (const char* nd : needles) {
        size_t nlen = strlen(nd);
        size_t scanned = 0;
        while (scanned + nlen < sz_) {
            const void* hit = MemFind(d_ + scanned, sz_ - scanned, nd, nlen);
            if (!hit) break;
            size_t pos = (size_t)((const u8*)hit - d_);
            scanned = pos + 1;

            // parse major.minor after the needle
            size_t vStart = pos + nlen;
            std::string ver;
            for (size_t i = vStart; i < sz_ && i < vStart + 16; i++) {
                char c = (char)d_[i];
                if ((c >= '0' && c <= '9') || c == '.') ver.push_back(c);
                else break;
            }
            // expect M.m[.p]
            if (!ver.empty() && seen.insert(ver).second) {
                out.push_back(std::string(nd) + ver);
            }
            if (out.size() >= 24) return out;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// YENI VERI TIPLERI: debug / import / resource / rich / tls / entropy / rtti
// ---------------------------------------------------------------------------

namespace {

const char* DebugTypeName(u32 t) {
    switch (t) {
        case 1:  return "COFF";
        case 2:  return "CodeView";
        case 3:  return "FPO";
        case 4:  return "MISC";
        case 6:  return "REPRO";
        case 7:  return "EXCEPTION";
        case 13: return "EXDLL";
        case 16: return "POGO";
        case 17: return "ILTCG";
        case 18: return "MPX";
        case 20: return "SPGO";
        default: return "?";
    }
}

// Guid -> standart "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" (uygulama cozumleyicisi)
std::string GuidToString(const u8* p) {
    char b[40];
    snprintf(b, sizeof(b),
             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             Rd32(p, 0), Rd16(p, 4), Rd16(p, 6),
             p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    return b;
}

// UTF-16LE null-terminated string oku (limit ile)
std::string ReadUtf16Z(const u8* d, size_t sz, size_t off, size_t maxChars = 96) {
    if (!d || off + 2 > sz) return "";
    std::string out;
    for (size_t i = 0; i < maxChars && off + i * 2 + 2 <= sz; i++) {
        u16 c = Rd16(d, off + i * 2);
        if (c == 0) break;
        if (c < 0x20 && c != '\t') break;
        if (c < 0x80) out += (char)c;
        else out += '?';    // sabit arama icin ascii disi onemsiz
    }
    return out;
}

std::string TrimStr(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

const char* RichToolName(u16 prodId) {
    switch (prodId) {
        case 0x0001: return "Import: Impl";
        case 0x0002: return "Import: STL";
        case 0x0003: return "Import: VC";
        case 0x0004: return "Import: GCC";
        case 0x000F: return "Import: ASM";
        case 0x001B: case 0x001F: return "RC (resource compiler)";
        case 0x0054: return "VC++ Compiler";
        case 0x005D: return "VC++ C1";
        case 0x0060: return "VC++ C1xx";
        case 0x006C: return "MASM";
        case 0x006D: return "Linker (VC6)";
        case 0x007D: return "PDB alt";
        case 0x009E: case 0x009F: case 0x00A2: return "Linker";
        case 0x00A6: return "ARM Compiler";
        case 0x00B0: return "ASM (ml64)";
        case 0x00B4: case 0x00BB: return "C Compiler (cl)";
        case 0x00C1: case 0x00C2: return "ASM/Linker";
        case 0x0103: return "Linker (VC12-)";
        case 0x0104: return "Linker (VC14+)";
        case 0x0107: case 0x010D: return "Compiler";
        case 0x0110: case 0x0112: case 0x0113: return "Compiler (cl)";
        case 0x0114: return "RC x64";
        case 0x0115: return "Linker (VC14.1+)";
        case 0x0120: case 0x0121: case 0x0124: return "Compiler (cl)";
        case 0x0127: case 0x013F: case 0x0141: case 0x0143: case 0x0144: return "Compiler (cl)";
        case 0x0147: case 0x014B: case 0x014E: return "Compiler (cl)";
        case 0x0153: case 0x0155: case 0x0157: case 0x015A: case 0x015E: return "Compiler (cl)";
        case 0x0164: case 0x0166: case 0x0167: case 0x016C: case 0x016D: case 0x0170: return "Compiler (cl)";
        case 0x0172: case 0x0173: case 0x0176: case 0x0177: case 0x017B: case 0x017F: return "Compiler (cl)";
        case 0x0181: case 0x0184: case 0x0188: case 0x018D: case 0x018F: return "Compiler (cl)";
        case 0x0191: case 0x0193: case 0x0194: case 0x0197: case 0x019C: return "Compiler (cl)";
        case 0x01A0: case 0x01A3: case 0x01A4: case 0x01A5: case 0x01A6: return "Compiler (cl)";
        case 0x01A7: case 0x01A8: case 0x01AA: case 0x01AB: case 0x01AC: case 0x01AD: return "Compiler (cl)";
        case 0x01AE: case 0x01AF: case 0x01B0: case 0x01B1: return "Compiler (cl)";
        default: return nullptr;
    }
}

constexpr u32 kEntSample = 1u << 20;   // 1 MiB orneklem

double ShannonEntropy(const u8* d, size_t n) {
    if (!d || n == 0) return 0.0;
    u32 hist[256] = {0};
    for (size_t i = 0; i < n; i++) hist[d[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!hist[i]) continue;
        const double p = (double)hist[i] / (double)n;
        e -= p * std::log2(p);
    }
    return e;
}

std::string PackerHintFor(const std::string& lowerName) {
    if (lowerName.rfind(".vmp", 0) == 0) return "VMProtect";
    if (lowerName.find("themida") != std::string::npos) return "Themida";
    if (lowerName.rfind("upx", 0) == 0) return "UPX";
    if (lowerName.find(".aspack") != std::string::npos || lowerName.find(".adata") != std::string::npos) return "ASPack";
    if (lowerName.find("petite") != std::string::npos) return "Petite";
    if (lowerName.find(".nsp") != std::string::npos) return "NsPack";
    if (lowerName.find(".enigma") != std::string::npos) return "Enigma";
    return "";
}

} // namespace

std::vector<PEDebugEntry> PEFile::DebugDirectory() const {
    std::vector<PEDebugEntry> out;
    if (!valid_) return out;
    const u32 rva = dataDirsRva_[6];
    const u32 dsize = dataDirsSize_[6];
    if (!rva || !dsize) return out;

    u32 off = RvaToOffset(rva);
    if (off == 0xFFFFFFFFu || off >= sz_) return out;
    const size_t n = std::min<size_t>(dsize / 28, 64);
    for (size_t i = 0; i < n; i++) {
        const size_t e = off + i * 28;
        if (e + 28 > sz_) break;
        PEDebugEntry de;
        de.type = Rd32(d_, e + 12);
        de.typeName = DebugTypeName(de.type);
        de.sizeOfData = Rd32(d_, e + 16);
        de.rva = Rd32(d_, e + 20);
        de.fileOff = Rd32(d_, e + 24);
        u32 dataOff = (de.rva && de.rva != 0xFFFFFFFFu) ? RvaToOffset(de.rva) : de.fileOff;
        if (dataOff == 0xFFFFFFFFu) dataOff = de.fileOff;
        if (de.type == 2 && dataOff + 4 <= sz_) {           // CodeView
            char fmt[5] = {0};
            memcpy(fmt, d_ + dataOff, 4);
            de.cvFormat = fmt;
            if (de.cvFormat == "RSDS" && dataOff + 24 <= sz_) {
                de.guid = GuidToString(d_ + dataOff + 4);
                de.age = Rd32(d_, dataOff + 20);
                const char* p = (const char*)(d_ + dataOff + 24);
                de.pdbPath.assign(p, strnlen(p, std::min<size_t>(sz_ - (dataOff + 24), 260)));
            } else if (de.cvFormat == "NB10" && dataOff + 16 <= sz_) {
                de.timestamp = Rd32(d_, dataOff + 4);
                de.age = Rd32(d_, dataOff + 12);
                const char* p = (const char*)(d_ + dataOff + 16);
                de.pdbPath.assign(p, strnlen(p, std::min<size_t>(sz_ - (dataOff + 16), 260)));
            } else if (de.cvFormat == "NB11" && dataOff + 12 <= sz_) {
                de.timestamp = Rd32(d_, dataOff + 4);
                de.age = Rd32(d_, dataOff + 8);
                const char* p = (const char*)(d_ + dataOff + 12);
                de.pdbPath.assign(p, strnlen(p, std::min<size_t>(sz_ - (dataOff + 12), 260)));
            }
        } else if (de.type == 4 && dataOff + 12 <= sz_) {   // MISC
            de.timestamp = Rd32(d_, dataOff + 4);
            u32 miscLen = Rd32(d_, dataOff + 8);
            miscLen = std::min<u32>(miscLen, 260);
            if (dataOff + 12 + miscLen <= sz_) {
                de.miscName.assign((const char*)d_ + dataOff + 12, miscLen);
                de.miscName.resize(strnlen(de.miscName.c_str(), de.miscName.size()));
            }
        }
        out.push_back(std::move(de));
    }
    return out;
}

std::vector<PEImportDll> PEFile::Imports() const {
    std::vector<PEImportDll> out;
    if (!valid_) return out;
    const u32 rva = dataDirsRva_[1];
    const u32 dsize = dataDirsSize_[1];
    if (!rva || !dsize) return out;

    u32 off = RvaToOffset(rva);
    if (off == 0xFFFFFFFFu || off + 20 > sz_) return out;
    constexpr size_t kMaxDlls = 256, kMaxFuncsPerDll = 128;

    for (size_t i = 0; i < kMaxDlls; i++) {
        const size_t desc = off + i * 20;
        if (desc + 20 > sz_) break;
        const u32 nameRva = Rd32(d_, desc + 12);
        const u32 oftRva  = Rd32(d_, desc + 0);
        const u32 ftRva   = Rd32(d_, desc + 16);
        if (!nameRva && !ftRva && !oftRva) break;   // null terminator

        PEImportDll dll;
        u32 nOff = RvaToOffset(nameRva);
        if (nOff != 0xFFFFFFFFu && nOff < sz_) {
            const char* p = (const char*)(d_ + nOff);
            dll.dllName.assign(p, strnlen(p, std::min<size_t>(sz_ - nOff, 128)));
        }
        if (dll.dllName.empty()) { dll.dllName = "?"; }

        // thunk tablosu: OriginalFirstThunk yoksa FirstThunk kullan
        u32 thunkRva = oftRva ? oftRva : ftRva;
        if (thunkRva) {
            u32 tOff = RvaToOffset(thunkRva);
            if (tOff != 0xFFFFFFFFu && tOff + 8 <= sz_) {
                for (u32 j = 0; j < 0x8000; j++) {
                    const size_t te = tOff + (size_t)j * 8;
                    if (te + 8 > sz_) break;
                    const u64 t = Rd64(d_, te);
                    if (t == 0) break;
                    dll.funcCount++;
                    if (dll.funcs.size() < kMaxFuncsPerDll) {
                        if (t & 0x8000000000000000ull) {
                            dll.funcs.push_back("Ordinal#" + std::to_string(t & 0xFFFFull));
                        } else {
                            u32 hnOff = RvaToOffset((u32)t);
                            if (hnOff != 0xFFFFFFFFu && hnOff + 2 <= sz_) {
                                const char* p = (const char*)(d_ + hnOff + 2);
                                std::string fn;
                                fn.assign(p, strnlen(p, std::min<size_t>(sz_ - (hnOff + 2), 96)));
                                dll.funcs.push_back(std::move(fn));
                            }
                        }
                    }
                }
            }
        }
        dll.delayedViaName = !oftRva && ftRva;
        out.push_back(std::move(dll));
    }
    return out;
}

PEVersionInfo PEFile::VersionResource() const {
    PEVersionInfo vi;
    if (!valid_) return vi;
    const u32 rva = dataDirsRva_[2];
    const u32 dsize = dataDirsSize_[2];
    if (!rva || !dsize) return vi;

    u32 off = RvaToOffset(rva);
    if (off == 0xFFFFFFFFu || off >= sz_) return vi;

    // VS_VERSIONINFO UTF-16 anahtarini kaynak havuzunda ara (tek gecis)
    const u16 needle[] = { 'V','S','_','V','E','R','S','I','O','N','_','I','N','F','O', 0 };
    const size_t limit0 = std::min<size_t>(sz_, off + dsize);
    const void* hit = (off < limit0)
        ? MemFind(d_ + off, limit0 - off, needle, sizeof(needle) - 2)
        : nullptr;
    if (!hit) return vi;    // VERSIONINFO kaynagi yok
    vi.present = true;
    vi.rva = rva;
    vi.size = dsize;

    // VS_FIXEDFILEINFO imza 0xFEEF04BD (LE: BD 04 EF FE) kaynak verisinde ara
    const u8 ffisig[4] = { 0xBD, 0x04, 0xEF, 0xFE };
    const void* ffiHit = MemFind(d_ + off, std::min<size_t>(sz_, off + dsize) - off, ffisig, 4);
    if (ffiHit) {
        size_t fOff = (size_t)((const u8*)ffiHit - d_);
        if (fOff + 52 <= sz_) {
            vi.fileMajor = Rd16(d_, fOff + 8);
            vi.fileMinor = Rd16(d_, fOff + 10);
            vi.fileRev   = Rd16(d_, fOff + 12);   // dwFileVersionMS low
            vi.fileBuild = Rd16(d_, fOff + 6);    // dwFileVersionMS high yanlis; asagida duzelt
            // dogru siralama: MS = major<<16 | minor ; LS = build<<16 | revision
            u32 fms = Rd32(d_, fOff + 8), fls = Rd32(d_, fOff + 12);
            vi.fileMajor = (u16)(fms >> 16);
            vi.fileMinor = (u16)(fms & 0xFFFF);
            vi.fileBuild = (u16)(fls >> 16);
            vi.fileRev   = (u16)(fls & 0xFFFF);
            u32 pms = Rd32(d_, fOff + 16), pls = Rd32(d_, fOff + 20);
            vi.prodMajor = (u16)(pms >> 16);
            vi.prodMinor = (u16)(pms & 0xFFFF);
            vi.prodBuild = (u16)(pls >> 16);
            vi.prodRev   = (u16)(pls & 0xFFFF);
            vi.flags = Rd32(d_, fOff + 24);
        }
    }

    // anahtar/deger ciftleri: UTF-16LE anahtar + null + pad + UTF-16 deger + null
    const char* keys[] = { "CompanyName", "ProductName", "FileDescription", "FileVersion",
                           "ProductVersion", "InternalName", "OriginalFilename",
                           "LegalCopyright", "Comments" };
    std::string* targets[] = { &vi.companyName, &vi.productName, &vi.fileDescription, &vi.fileVersion,
                               &vi.productVersion, &vi.internalName, &vi.originalFilename,
                               &vi.legalCopyright, &vi.comments };
    const size_t limit = std::min<size_t>(sz_, off + dsize);
    for (size_t k = 0; k < 9; k++) {
        // UTF-16LE anahtari derle
        std::vector<u16> nk;
        for (const char* c = keys[k]; *c; c++) nk.push_back((u16)(u8)*c);
        nk.push_back(0);
        size_t scan = off;
        bool found = false;
        // en fazla 16 eslesme dene (kotu dosyalarda O(n^2) kilitlenmeyi onler)
        int tries = 0;
        while (scan + nk.size() * 2 <= limit && tries++ < 16) {
            const void* h = MemFind(d_ + scan, limit - scan, nk.data(), nk.size() * 2);
            if (!h) break;
            size_t p = (size_t)((const u8*)h - d_) + nk.size() * 2;
            // degeri oku (null + 0..3 u16 pad sonrasi); hiza degisken olabilir
            std::string val;
            for (int pad = 0; pad <= 3 && val.empty(); pad++)
                val = TrimStr(ReadUtf16Z(d_, sz_, p + (size_t)pad * 2, 128));
            if (val.empty()) { scan = (size_t)((const u8*)h - d_) + nk.size() * 2; continue; }
            *targets[k] = val;
            found = true;
            break;
        }
        (void)found;
    }
    return vi;
}

PERichHeader PEFile::RichHeader() const {
    PERichHeader rh;
    if (!valid_ || !d_ || sz_ < 0x80) return rh;

    // "Rich" imzasi DOS stub'da (ilk 0x400 bayt)
    const u8 richMagic[4] = { 'R', 'i', 'c', 'h' };
    const void* hit = MemFind(d_, std::min<size_t>(sz_, 0x400), richMagic, 4);
    if (!hit) return rh;
    const size_t richOff = (size_t)((const u8*)hit - d_);
    if (richOff + 8 > sz_) return rh;
    rh.key = Rd32(d_, richOff + 4);

    // DanS basligi geriye dogru XOR'lu tara (en fazla 0x100 bayt)
    const size_t scanStart = richOff > 0x100 ? richOff - 0x100 : 0;
    size_t dansOff = 0;
    bool found = false;
    for (size_t p = richOff - 4; p >= scanStart && p >= 4; p -= 4) {
        const u32 v = Rd32(d_, p) ^ rh.key;
        if (v == 0x536E6144u) {   // "DanS" LE
            dansOff = p;
            found = true;
            break;
        }
        if (richOff - p > 0x100) break;
    }
    if (!found || dansOff + 16 > richOff) return rh;
    rh.present = true;
    rh.offset = (u32)dansOff;

    // girisler: DanS + 3 pad dword sonrasi, "Rich" imzasina kadar (id,count) ciftleri
    size_t p = dansOff + 16;
    for (int i = 0; p + 8 <= richOff && i < 64; i++, p += 8) {
        const u32 id = Rd32(d_, p) ^ rh.key;
        const u32 count = Rd32(d_, p + 4) ^ rh.key;
        if (!id) continue;      // pad
        PERichEntry e;
        e.prodId = (u16)(id >> 16);
        e.build = (u16)(id & 0xFFFF);
        e.count = count;
        if (const char* n = RichToolName(e.prodId)) e.toolName = n;
        else { char b[32]; snprintf(b, sizeof(b), "Tool 0x%04X", e.prodId); e.toolName = b; }
        rh.tools.push_back(std::move(e));
    }
    return rh;
}

std::vector<PETlsCallback> PEFile::TlsCallbacks() const {
    std::vector<PETlsCallback> out;
    if (!valid_) return out;
    const u32 rva = dataDirsRva_[9];
    if (!rva) return out;
    u32 off = RvaToOffset(rva);
    if (off == 0xFFFFFFFFu || off + 24 > sz_) return out;

    // IMAGE_TLS_DIRECTORY64: start(8) end(8) index(8) callbacks(8) zerofill(4) chars(4)
    const u64 cbVa = Rd64(d_, off + 24);
    if (!cbVa) return out;
    if (cbVa < imgBase_) return out;
    const u64 cbRva = cbVa - imgBase_;
    u32 cbOff = RvaToOffset((u32)cbRva);
    if (cbOff == 0xFFFFFFFFu) return out;

    for (u32 i = 0; i < 32; i++) {
        const size_t e = cbOff + (size_t)i * 8;
        if (e + 8 > sz_) break;
        const u64 fnVa = Rd64(d_, e);
        if (!fnVa) break;   // null-terminated
        PETlsCallback cb;
        cb.va = fnVa;
        if (fnVa >= imgBase_) cb.rva = (u32)(fnVa - imgBase_);
        if (const PESection* s = SectionAtRva(cb.rva)) cb.section = s->name;
        out.push_back(std::move(cb));
    }
    return out;
}

std::vector<PESectionEntropy> PEFile::SectionEntropy() const {
    std::vector<PESectionEntropy> out;
    if (!valid_) return out;
    for (const PESection& s : secs_) {
        PESectionEntropy se;
        se.name = s.name;
        se.rawSize = s.rawSize;
        se.packerHint = PackerHintFor(str::Lower(s.name));
        if (s.rawSize && s.rawOff != 0xFFFFFFFFu) {
            const size_t off = s.rawOff;
            if (off < sz_) {
                const size_t n = std::min<size_t>(s.rawSize, std::min<size_t>(kEntSample, sz_ - off));
                se.entropy = ShannonEntropy(d_ + off, n);
            }
        }
        se.high = se.entropy >= 7.2;
        out.push_back(std::move(se));
    }
    return out;
}

std::vector<PERttiClass> PEFile::RttiClasses(size_t maxScan) const {
    // MSVC x64 RTTI (tek gecisli COL->TypeDescriptor esleştirme):
    //   CompleteObjectLocator (24 bayt): sig(4) off(4) cdOff(4) typeDescRVA(4) classDescRVA(4) selfRVA(4)
    //   TypeDescriptor: vptr(8) spare(8) name(".?AV...@@")
    //   ClassHierarchyDescriptor: sig(4) attribute(4) numBases(4) baseArrayRVA(4)
    std::vector<PERttiClass> out;
    if (!valid_ || !d_) return out;

    struct ColInfo {
        u32 colRva = 0, chdRva = 0;
        bool virtualBase = false;
    };
    // tdRva -> COL bilgisi (ayni bolumde olmasa da RVAdan eslesir)
    std::unordered_map<u32, ColInfo> colsByTd;
    std::unordered_set<u32> seenCols;
    size_t scanned = 0;

    // 1. gecis: tum veri bolumlerinde COL sekli tara (kendine referans zorunlu)
    for (const PESection& s : secs_) {
        if (s.exec || !s.vs) continue;
        u32 off = RvaToOffset(s.va);
        if (off == 0xFFFFFFFFu || off >= sz_) continue;
        const size_t secLen = std::min<size_t>(s.vs, std::min<size_t>(sz_ - off, 64u << 20));
        if (secLen < 24) continue;
        const u8* base = d_ + off;
        const u32 secRva = s.va;
        for (size_t c = 0; c + 24 <= secLen && scanned < maxScan; c += 4, scanned++) {
            const u32 self = Rd32(base, c + 20);
            if (self != secRva + (u32)c) continue;       // x64: pSelf == self RVA
            const u32 sig = Rd32(base, c);
            if (sig > 1) continue;                        // 0: imagebase goreli, 1: vdso
            const u32 tdRva = Rd32(base, c + 12);
            const u32 chdRva = Rd32(base, c + 16);
            if (!tdRva || !chdRva || tdRva >= sizeImage_ || chdRva >= sizeImage_) continue;
            // COL kendisi veri bolumunde olmali; td RVA da goruntude olmali
            if (seenCols.insert(secRva + (u32)c).second) {
                colsByTd[tdRva] = { secRva + (u32)c, chdRva, sig == 1 };
            }
        }
        if (scanned >= maxScan) break;
    }

    // 2. gecis: ".?A" TypeDescriptor adlari -> COL eslesmesi
    for (const PESection& s : secs_) {
        if (s.exec || !s.vs) continue;
        u32 off = RvaToOffset(s.va);
        if (off == 0xFFFFFFFFu || off >= sz_) continue;
        const size_t secLen = std::min<size_t>(s.vs, std::min<size_t>(sz_ - off, 64u << 20));
        if (secLen < 40) continue;
        const u8* base = d_ + off;
        const u32 secRva = s.va;

        size_t i = 0;
        while (i + 40 < secLen) {
            if (base[i] != '.' || base[i + 1] != '?' || base[i + 2] != 'A') { i++; continue; }
            const size_t nameOff = i;

            // TypeDescriptor basi: name - 16 (vptr 8 + spare 8); RVA bolum icinde kalmali
            if (nameOff < 16) { i = nameOff + 1; continue; }
            const u32 tdRva = secRva + (u32)nameOff - 16;   // TypeDescriptor baslangic RVA'si

            // isim sonu: "@@" ile biter (capi 256)
            const size_t maxName = std::min<size_t>(256, secLen - nameOff);
            size_t nameEnd = 0;
            while (nameEnd + 2 < maxName) {
                const u8 c = base[nameOff + nameEnd];
                if (c == '@' && base[nameOff + nameEnd + 1] == '@') break;
                if (c < 0x20 || c >= 0x7f) break;
                nameEnd++;
            }
            if (nameEnd < 4 || nameEnd + 2 >= maxName) { i = nameOff + 1; continue; }

            // bu TypeDescriptor'a COL referans veriyor mu?
            auto it = colsByTd.find(tdRva);
            if (it == colsByTd.end()) { i = nameOff + 1; continue; }

            PERttiClass rc;
            rc.virtualBase = it->second.virtualBase;
            rc.colRva = it->second.colRva;
            rc.typeDescRva = tdRva;
            rc.classDescRva = it->second.chdRva;
            rc.mangled.assign((const char*)(base + nameOff), nameEnd + 2);

            // CHD oku (bolumler arasi olabilir)
            u32 chdOff = RvaToOffset(it->second.chdRva);
            if (chdOff != 0xFFFFFFFFu && chdOff + 16 <= sz_ && Rd32(d_, chdOff) <= 1) {
                rc.numBases = Rd32(d_, chdOff + 8);
            }

            // demangle: ".?AV" -> class, ".?AU" -> struct, ".?AW4" -> enum, ".?AR" -> const
            const std::string m = rc.mangled;
            const char tch = m.size() > 3 ? m[3] : '?';
            std::string kind;
            size_t ns = 4;
            if (tch == 'V') kind = "class";
            else if (tch == 'U') kind = "struct";
            else if (tch == 'W') { kind = "enum"; if (m.size() > 4 && m[4] == '4') ns = 5; }
            else if (tch == 'R') kind = "const";
            else if (tch == '?') kind = "template";
            std::string body = m.substr(ns);
            if (body.size() >= 2 && body.compare(body.size() - 2, 2, "@@") == 0)
                body = body.substr(0, body.size() - 2);
            // bileşenler "@" ile ayrilir -> ters sirada "::" ile birlesir
            std::vector<std::string> parts;
            size_t st = 0;
            while (st < body.size() && parts.size() < 16) {
                const size_t at = body.find('@', st);
                if (at == std::string::npos) { parts.push_back(body.substr(st)); break; }
                parts.push_back(body.substr(st, at - st));
                st = at + 1;
            }
            std::string dem;
            for (size_t k2 = parts.size(); k2-- > 0;) {
                if (!dem.empty()) dem += "::";
                dem += parts[k2];
            }
            rc.name = kind.empty() ? dem : kind + " " + dem;

            out.push_back(std::move(rc));
            if (out.size() >= 4096) return out;
            i = nameOff + nameEnd + 2;
        }
    }
    return out;
}

} // namespace dumper
