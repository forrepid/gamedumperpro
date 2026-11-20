// ============================================================================
// DumperPro - Il2CppBinary.cpp
//
// IL2CPP binary eslestirmesi uygulamas. Layout sabitleri il2cpp runtime
// kaynaklarindan (Il2CppDumper yansimalari ile) dogrulanmistir:
//
//   Il2CppCodeGenModule  : name(+0), methodPointerCount(+8), methodPointers(+0x10)
//   Il2CppMetadataRegistration (x64): genericClasses(+0x08), genericInsts(+0x18),
//        genericMethodTable(+0x28), typesCount(+0x30), types(+0x38),
//        methodSpecs(+0x48), fieldOffsetsCount(+0x50), fieldOffsets(+0x58)
//        (x86 4 bayt alanlarda: typesCount(+0x18), types(+0x1C),
//         fieldOffsetsCount(+0x28), fieldOffsets(+0x2C))
//   Il2CppType (x64, 16B): data(+0), bits(+8): attrs:16|type:8|num_mods:5|byref@30|pinned@31
//   Il2CppClass: image(+0), gc_desc(+8), name(+0x10), namespaze(+0x18)
//   Il2CppGenericClass: type(+0), context.class_inst(+8), context.method_inst(+0x10)
//   Il2CppGenericInst: type_argc(+0), type_argv(+8)
//   Il2CppArrayType: etype(+0), rank(+8), sizes(+0x10), lobounds(+0x18)
//
// ELF PIE destegi: SHT_RELA (4) bolumlerindeki R_*_RELATIVE kayitlari okunur
// (x86-64: type 8, AArch64: 1027, RISC-V: 3); slot degeri = addend.
// PE tarafinda ham gostericiler ImageBase ile RVA'ya normalize edilir.
//
// METADATA USAGES (v19..24.5, Il2CppDumper StructGenerator.cs dogrulamasi):
//   MetadataRegistration.metadataUsages (x64 +0x70 count, +0x78 ptr) bir
//   gosterci dizisidir; her elemanin DEGERI kodgen global hucrenin VA'sidir
//   (g_MyClass_TypeInfo gibi; cogunlukla .bss'te). Metadata tarafindaki
//   list/pair tablolari hangi hucreye hangi kaydin (TypeInfo/Il2CppType/
//   MethodDef/FieldInfo/StringLiteral/MethodRef) baglanacagini soyler.
//   DumperPro slot degerlerini okur (ELF RELA reloc uyumlu), hucreleri
//   InDataCell (map'li VEYA bss) ile dogrular ve il2cpp_usages.txt +
//   script.json ScriptMetadata bolumlerini uretir.
//
// ONEMLI NOTLAR:
//   1) Tum okumalar sinir kontrollu; bozuk/eksik binary'de kismi sonuc +
//      lastError doner, crash olmaz. Dogrulama gecmeyen adaylardan adres
//      URETILMEZ (sessiz tahmin yok).
//   2) Cikti uretici fonksiyonlari ham binary veriyi de alir; tip cozumu
//      icin BinaryView yeniden kurulur (tek gecis, ucuz).
//   3) Kullanim siniri: yalnizca sahibi olunan/lisansli yazilimin analizi.
// ============================================================================

#include "il2cpp/Il2CppBinary.h"
#include "il2cpp/Il2Cpp.h"
#include "file/UniFormat.h"
#include "core/PEFile.h"
#include "utils/StrUtil.h"
#include "utils/Logger.h"

#include <cstring>
#include <cstdlib>
#include <unordered_set>

namespace dumper {

namespace {

// ---- little-endian okuyucular ----------------------------------------------
u32 Rd32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
u64 Rd64(const u8* p) { return (u64)Rd32(p) | ((u64)Rd32(p + 4) << 32); }

// ---- BinaryView: PE/ELF uzerinde VA tabanli tekil okuma katmani ------------
struct Sec {
    u64 va = 0;       // VA (ELF PIE: base 0 goreli; PE: ImageBase dahil)
    u64 size = 0;
    u64 off = 0;      // dosya ofseti
    bool exec = false;
    bool write = false;
};

struct BinaryView {
    const u8* d = nullptr;
    size_t sz = 0;
    int bits = 64;
    u32 ps = 8;               // pointer size
    u64 imageBase = 0;        // PE: ImageBase; ELF: 0
    std::vector<Sec> secs;
    // dosyada verisi olmayan (NOBITS/.bss benzeri) YAZILABILIR bolgeler:
    // kodgen global huceleri (g_X_TypeInfo) cogunlukla burada yasar
    std::vector<std::pair<u64, u64>> bssRanges;
    // ELF RELA RELATIVE relocation: slot VA -> addend
    std::unordered_map<u64, u64> relocs;
    // dosya ofseti -> VA (sorted by offset)
    std::vector<std::pair<u64, u64>> offToVa;

    bool MapVa(u64 va, u64& off) const {
        for (const Sec& s : secs) {
            if (va >= s.va && va - s.va < s.size) {
                off = s.off + (va - s.va);
                return off < sz;
            }
        }
        return false;
    }
    bool MapOff(u64 off, u64& va) const {
        size_t lo = 0, hi = offToVa.size();
        while (lo < hi) {
            const size_t mid = (lo + hi) / 2;
            if (offToVa[mid].first <= off) lo = mid + 1;
            else hi = mid;
        }
        if (lo == 0) return false;
        const auto& e = offToVa[lo - 1];
        va = e.second + (off - e.first);
        return true;
    }
    bool InExec(u64 va) const {
        for (const Sec& s : secs)
            if (s.exec && va >= s.va && va - s.va < s.size) return true;
        return false;
    }
    bool InAny(u64 va) const {
        for (const Sec& s : secs)
            if (va >= s.va && va - s.va < s.size) return true;
        return false;
    }
    // dosyada verisi olmayan yazi-bolgesi (bss) kontrolu
    bool InBss(u64 va) const {
        for (const auto& r : bssRanges)
            if (va >= r.first && va - r.first < r.second) return true;
        return false;
    }
    // veri hucresi: map'lenmis VEYA bss (usage hucre dogrulamasinda kullanilir)
    bool InDataCell(u64 va) const { return InAny(va) || InBss(va); }

    // VA'da duran gosterci: ELF RELA varsa addend, yoksa ham deger
    u64 ReadPtrVa(u64 va, bool& ok, bool& fromReloc) const {
        ok = false; fromReloc = false;
        auto it = relocs.find(va);
        if (it != relocs.end()) {
            ok = true; fromReloc = true;
            return it->second;
        }
        u64 off = 0;
        if (!MapVa(va, off)) return 0;
        if (off + ps > sz) return 0;
        ok = true;
        return ps == 8 ? Rd64(d + off) : (u64)Rd32(d + off);
    }
    u32 ReadU32Va(u64 va, bool& ok) const {
        ok = false;
        u64 off = 0;
        if (!MapVa(va, off) || off + 4 > sz) return 0;
        ok = true;
        return Rd32(d + off);
    }
    std::string ReadCStrVa(u64 va, size_t cap = 160) const {
        u64 off = 0;
        if (!MapVa(va, off)) return "";
        const size_t maxLen = std::min<size_t>(sz - off, cap);
        size_t len = 0;
        while (len < maxLen && d[off + len] != 0 && d[off + len] >= 0x20 && d[off + len] < 0x7f) len++;
        return std::string((const char*)d + off, len);
    }
};

// ---- BinaryView kurulum -----------------------------------------------------
bool BuildElfView(const u8* d, size_t sz, BinaryView& v, std::string& arch) {
    ElfInfo elf;
    if (!UniFormat::ParseElf(d, sz, elf) || !elf.valid) return false;
    v.bits = elf.bits;
    v.ps = elf.bits == 64 ? 8 : 4;
    v.imageBase = 0;
    v.d = d;
    v.sz = sz;
    arch = elf.machine;
    for (const ElfSection& s : elf.sections) {
        if (!s.alloc) continue;
        if (s.typeName == "NOBITS") {
            // .bss: dosyada veri yok ama calisma zamaninda yazi-bolgesi
            if (s.size > 0) v.bssRanges.emplace_back(s.addr, s.size);
            continue;
        }
        if (s.size == 0) continue;
        Sec sec;
        sec.va = s.addr;
        sec.size = s.size;
        sec.off = s.offset;
        sec.exec = s.exec;
        sec.write = s.write;
        if (sec.off < sz) v.secs.push_back(sec);
        if (sec.off + sec.size <= sz) v.offToVa.emplace_back(sec.off, sec.va);
    }

    // relocations: SHT_RELA (4) / SHT_REL (9) bolumleri
    const bool is64 = elf.bits == 64;
    for (const ElfSection& s : elf.sections) {
        const bool rela = s.typeName == "RELA";
        const bool rel  = s.typeName == "REL";
        if (!rela && !rel) continue;
        const u64 entSz = is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
        if (entSz == 0 || s.size < entSz) continue;
        const u64 count = std::min<u64>(s.size / entSz, 4000000);
        for (u64 i = 0; i < count; i++) {
            const u64 eOff = s.offset + i * entSz;
            if (eOff + entSz > sz) break;
            u64 rOff = 0, rInfo = 0, addend = 0;
            if (is64) {
                rOff = Rd64(d + eOff);
                rInfo = Rd64(d + eOff + 8);
                if (rela) addend = Rd64(d + eOff + 16);
            } else {
                rOff = Rd32(d + eOff);
                rInfo = Rd32(d + eOff + 4);
                if (rela) addend = Rd32(d + eOff + 8);
            }
            const u64 rtype = is64 ? (rInfo & 0xFFFFFFFFu) : (rInfo & 0xFFu);
            // RELATIVE: x86-64=8, AArch64=1027, RISC-V=3, i386=8(REL), ARM32=23(REL)
            const bool relative = (rtype == 8) || (rtype == 1027) || (rtype == 3) || (rtype == 23);
            if (relative && rela) v.relocs[rOff] = addend;
            // REL: slot zaten degeri tutar (map'e gerek yok)
        }
    }
    std::sort(v.offToVa.begin(), v.offToVa.end());
    return !v.secs.empty();
}

bool BuildPeView(const u8* d, size_t sz, BinaryView& v, std::string& arch) {
    PEFile pe;
    if (!pe.Parse(d, sz, false) || !pe.Valid()) return false;
    v.bits = 64;
    v.ps = 8;
    v.imageBase = pe.ImageBase();
    v.d = d;
    v.sz = sz;
    arch = "x86-64";
    for (const PESection& s : pe.Sections()) {
        if (s.rawSize == 0) {
            // BSS benzeri: virtual size > 0, raw 0 (nadir ama gecerli)
            if (s.vs > 0) v.bssRanges.emplace_back(v.imageBase + s.va, s.vs);
            continue;
        }
        Sec sec;
        sec.va = v.imageBase + s.va;
        sec.size = s.rawSize;                    // dosyada mevcut kismi
        sec.off = s.rawOff;
        sec.exec = s.exec;
        sec.write = s.write;
        if (sec.off < sz) v.secs.push_back(sec);
        if (sec.off + sec.size <= sz) v.offToVa.emplace_back(sec.off, sec.va);
        // virtual size raw'i asarsa tasi bss olarak kaydet (PE .bss kuyrugu)
        if (s.vs > s.rawSize)
            v.bssRanges.emplace_back(v.imageBase + s.va + s.rawSize, s.vs - s.rawSize);
    }
    std::sort(v.offToVa.begin(), v.offToVa.end());
    return !v.secs.empty();
}

// format sniff + view kurulum (cikti uretiminde de kullanilir)
bool BuildAnyView(const u8* d, size_t sz, BinaryView& v, std::string& arch) {
    const std::string magic = UniFormat::SniffMagic(d, sz);
    if (magic == "pe")  return BuildPeView(d, sz, v, arch);
    if (magic == "elf") return BuildElfView(d, sz, v, arch);
    return false;
}

// ---- yardimcilar -------------------------------------------------------------
std::vector<u64> FindAllNeedle(const u8* d, size_t sz, const std::string& needle, size_t cap) {
    std::vector<u64> hits;
    if (needle.empty() || needle.size() + 1 > sz) return hits;
    std::vector<u8> pat(needle.begin(), needle.end());
    pat.push_back(0); // NUL-sonlandirilmis C string
    const u8* begin = d;
    const u8* end = d + sz;
    const u8* cur = begin;
    while (hits.size() < cap) {
        const u8* p = std::search(cur, end, pat.begin(), pat.end());
        if (p == end) break;
        hits.push_back((u64)(p - begin));
        cur = p + 1;
    }
    return hits;
}

// Il2CppTypeEnum -> C# tip adi
std::string PrimTypeName(u32 t) {
    switch (t) {
        case 0x01: return "void";
        case 0x02: return "bool";
        case 0x03: return "char";
        case 0x04: return "sbyte";
        case 0x05: return "byte";
        case 0x06: return "short";
        case 0x07: return "ushort";
        case 0x08: return "int";
        case 0x09: return "uint";
        case 0x0A: return "long";
        case 0x0B: return "ulong";
        case 0x0C: return "float";
        case 0x0D: return "double";
        case 0x0E: return "string";
        case 0x16: return "TypedReference";
        case 0x18: return "IntPtr";
        case 0x19: return "UIntPtr";
        case 0x1C: return "object";
        default:   return "";
    }
}

// ---- Il2CppType isim cozucu -------------------------------------------------
struct TypeResolver {
    const BinaryView& v;
    const Il2Metadata& meta;
    bool versionAtLeast23;
    int depth = 0;
    static constexpr int kMaxDepth = 10;

    TypeResolver(const BinaryView& bv, const Il2Metadata& m)
        : v(bv), meta(m), versionAtLeast23(m.version >= 23) {}

    std::string Resolve(u64 typePtrVa, std::unordered_set<u64>& visited) {
        if (!typePtrVa || depth >= kMaxDepth) return "?";
        u64 off = 0;
        if (!v.MapVa(typePtrVa, off)) return "?";
        const u32 dataSz = v.ps;
        if (off + dataSz + 4 > v.sz) return "?";

        u64 dataVal = 0;
        if (v.ps == 8) {
            bool ok = false, fr = false;
            dataVal = v.ReadPtrVa(typePtrVa, ok, fr); // reloc oncelikli
        } else {
            dataVal = Rd32(v.d + off);
        }
        const u32 bitsWord = Rd32(v.d + off + dataSz);
        const u32 type = (bitsWord >> 16) & 0xFFu;
        const bool byref = ((bitsWord >> 30) & 1u) != 0;
        const bool pinned = ((bitsWord >> 31) & 1u) != 0;

        std::string inner = ResolveInner(dataVal, type, visited, typePtrVa);
        if (byref && inner.rfind("ref ", 0) != 0) inner = "ref " + inner;
        if (pinned) inner = "pinned " + inner;
        return inner;
    }

    std::string ResolveInner(u64 dataVal, u32 type, std::unordered_set<u64>& visited, u64 selfVa) {
        std::string prim = PrimTypeName(type);
        if (!prim.empty()) return prim;

        if (depth > 0 && visited.count(selfVa)) return "recursive";
        visited.insert(selfVa);
        DepthGuard g(*this);
        bool ok = false, fr = false;

        switch (type) {
            case 0x0F: { // PTR: data = Il2CppType*
                if (!dataVal) return "void*";
                return Resolve(dataVal, visited) + "*";
            }
            case 0x10:   // BYREF: byref biti Resolve() tarafindan eklenir
                return Resolve(dataVal, visited);
            case 0x11:   // VALUETYPE
            case 0x12: { // CLASS
                if (!versionAtLeast23) {
                    const i64 idx = (i64)(i32)(u32)dataVal;
                    if (idx >= 0 && (u64)idx < meta.types.size()) {
                        const Il2TypeInfo& t = meta.types[(size_t)idx];
                        return t.ns.empty() ? t.name : t.ns + "." + t.name;
                    }
                    return "?";
                }
                const u64 klass = dataVal;
                if (!klass || !v.InAny(klass)) return "?";
                const u64 namePtr = v.ReadPtrVa(klass + 0x10, ok, fr);
                if (!ok || !namePtr) return "?";
                const std::string name = v.ReadCStrVa(namePtr);
                const u64 nsPtr = v.ReadPtrVa(klass + 0x18, ok, fr);
                const std::string ns = (ok && nsPtr) ? v.ReadCStrVa(nsPtr) : "";
                if (name.empty()) return "?";
                return ns.empty() ? name : ns + "." + name;
            }
            case 0x13: return "!" + std::to_string((u32)dataVal);   // VAR
            case 0x1E: return "!!" + std::to_string((u32)dataVal);  // MVAR
            case 0x14: { // ARRAY: Il2CppArrayType{ etype(+0), rank(+8), ... }
                if (!dataVal || !v.InAny(dataVal)) return "?[]";
                const u64 elemTypePtr = v.ReadPtrVa(dataVal, ok, fr);
                bool rok = false;
                const u32 rank = v.ReadU32Va(dataVal + 8, rok);
                std::string e = (ok && elemTypePtr) ? Resolve(elemTypePtr, visited) : "?";
                const u32 r = rok ? std::max<u32>(rank, 1) : 1u;
                return e + (r <= 1 ? "[]" : "[" + std::to_string(r) + "]");
            }
            case 0x15: { // GENERICINST: Il2CppGenericClass{ type(+0), class_inst(+8), ... }
                if (!dataVal || !v.InAny(dataVal)) return "?";
                const u64 openTypePtr = v.ReadPtrVa(dataVal, ok, fr);
                std::string base = (ok && openTypePtr) ? Resolve(openTypePtr, visited) : "?";
                const u64 instPtr = v.ReadPtrVa(dataVal + 8, ok, fr);
                if (ok && instPtr && v.InAny(instPtr)) {
                    const u32 argc = v.ReadU32Va(instPtr, ok);
                    if (ok && argc >= 1 && argc <= 16) {
                        const u64 argvPtr = v.ReadPtrVa(instPtr + 8, ok, fr);
                        if (ok && argvPtr) {
                            std::string args = "<";
                            for (u32 k = 0; k < argc; k++) {
                                bool tok = false, tor = false;
                                const u64 argType = v.ReadPtrVa(argvPtr + (u64)k * v.ps, tok, tor);
                                if (k) args += ", ";
                                args += (tok && argType) ? Resolve(argType, visited) : "?";
                            }
                            args += ">";
                            base += args;
                        }
                    }
                }
                return base;
            }
            case 0x1D: { // SZARRAY: data = Il2CppType*
                return Resolve(dataVal, visited) + "[]";
            }
            default:
                return "?";
        }
    }

    struct DepthGuard {
        TypeResolver& r;
        explicit DepthGuard(TypeResolver& rr) : r(rr) { r.depth++; }
        ~DepthGuard() { r.depth--; }
    };
};

// tip indexi -> isim (TypeLookup uzerinden)
std::string ResolveTypeIdx(const BinaryView* v, const Il2BinaryResult* bin,
                           const Il2Metadata& meta, i32 typeIndex,
                           std::unordered_set<u64>& visited, TypeResolver& res) {
    if (typeIndex < 0) return "?";
    if (v && bin && bin->typesResolved && bin->typesVa) {
        bool pr = false, prel = false;
        const u64 tp = v->ReadPtrVa(bin->typesVa + (u64)typeIndex * v->ps, pr, prel);
        if (pr && tp) return res.Resolve(tp, visited);
        return "T<" + std::to_string(typeIndex) + ">";
    }
    return "T<" + std::to_string(typeIndex) + ">";
}

// ---- cikti icin ortak yardimcilar -------------------------------------------
std::string KindOf2(const Il2TypeInfo& t) {
    if (t.isEnum) return "enum";
    if (t.isInterface) return "interface";
    if (t.isValueType) return "struct";
    return "class";
}

std::string ModifiersOf2(const Il2TypeInfo& t) {
    std::string m = "public";
    if (t.flags & 0x80u) m += " abstract";
    if (t.flags & 0x100u) m += " sealed";
    return m;
}

std::string MethodAccess2(u16 flags) {
    switch (flags & 0x7u) {
        case 6: return "public";
        case 4: return "protected";
        case 3: return "internal";
        default: return "private";
    }
}

std::string FieldAccess2(u16 flags) {
    switch (flags & 0x7u) {
        case 6: return "public";
        case 4: return "protected";
        case 3: return "internal";
        default: return "private";
    }
}

std::string JsonEsc2(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 16);
    for (unsigned char ch : in) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", ch); out += b; }
                else out += (char)ch;
        }
    }
    return out;
}

std::string HexT(u32 t) { char b[16]; snprintf(b, sizeof(b), "0x%08X", t); return b; }

// metod index -> tip index (t.methodStart araligi ile)
i32 TypeOfMethod(const Il2Metadata& meta, u32 methodIndex) {
    for (size_t i = 0; i < meta.types.size(); i++) {
        const Il2TypeInfo& t = meta.types[i];
        if (methodIndex >= t.methodStart && methodIndex < t.methodStart + t.methodCount)
            return (i32)i;
    }
    return -1;
}

} // namespace

// ============================================================================
// Match
// ============================================================================
bool Il2CppBinaryMatch::Match(const u8* bin, size_t binSize, const Il2Metadata& meta,
                              Il2BinaryResult& out) {
    out = Il2BinaryResult{};
    if (!bin || binSize == 0 || !meta.valid) {
        out.lastError = "binary veya metadata gecersiz";
        return false;
    }

    BinaryView v;
    std::string arch;
    if (!BuildAnyView(bin, binSize, v, arch)) {
        out.lastError = "binary PE/ELF olarak ayristirilamadi";
        return false;
    }
    out.format = UniFormat::SniffMagic(bin, binSize);
    out.bits = v.bits;
    out.arch = arch;
    out.imageBase = v.imageBase;
    out.metadataVersion = meta.versionStr;
    out.mode = meta.version >= 24 ? "codegen-modules" : "flat";

    // ---- metadata: metod -> image haritasi ---------------------------------
    // image.typeStart..+typeCount araligindaki tiplerin metodlari o image'e
    // aittir (nested tipler dahil).
    std::vector<i32> methodToImage(meta.methods.size(), -1);
    for (u32 im = 0; im < meta.images.size(); im++) {
        const Il2ImageInfo& img = meta.images[im];
        for (u32 t = 0; t < img.typeCount; t++) {
            const u64 ti = (u64)img.typeStart + t;
            if (ti >= meta.types.size()) break;
            const Il2TypeInfo& ty = meta.types[ti];
            for (u32 m = 0; m < ty.methodCount; m++) {
                const u64 mi = (u64)ty.methodStart + m;
                if (mi < methodToImage.size() && methodToImage[mi] < 0)
                    methodToImage[mi] = (i32)im;
            }
        }
    }

    // ---- image adlarini binary string olarak ara ---------------------------
    // IL2CPP modul adlari C string olarak .rodata'dadir ("mscorlib.dll\0").
    const size_t kMaxHitsPerImage = 32;
    std::unordered_multimap<u64, u32> stringVaToImage;
    for (u32 im = 0; im < meta.images.size(); im++) {
        const std::string& name = meta.images[im].name;
        if (name.empty() || name[0] == '<' || name.size() > 96) continue;
        std::vector<u64> offs = FindAllNeedle(bin, binSize, name, kMaxHitsPerImage);
        for (u64 o : offs) {
            u64 va = 0;
            if (v.MapOff(o, va)) stringVaToImage.emplace(va, im);
        }
    }
    if (stringVaToImage.empty()) {
        out.lastError = "image adlari binary icinde bulunamadi (farkli build/obfuscation olabilir)";
        return false;
    }

    // ---- Il2CppCodeGenModule adaylarini bul -------------------------------
    // Aday: data bolumundeki slot p; p+0 -> string VA, p+8 u32 count,
    // p+0x10 -> methodPointers dizisi (exec'e isaret eden gostericiler).
    struct Candidate {
        u32 imageIndex = 0;
        u64 moduleVa = 0;
        u32 count = 0;
        u64 methodPointersVa = 0;
        double execRatio = 0.0;
    };
    std::vector<Candidate> candidates;
    std::unordered_set<u64> seenModules;
    bool okR = false, frR = false;

    for (const Sec& s : v.secs) {
        if (s.exec) continue;
        const u64 secEnd = s.va + s.size;
        for (u64 va = s.va; va + (v.ps == 8 ? 0x18 : 0x10) <= secEnd && candidates.size() < 4096; va += v.ps) {
            u64 val = 0;
            {
                auto it = v.relocs.find(va);
                if (it != v.relocs.end()) { val = it->second; }
                else {
                    u64 off = 0;
                    if (!v.MapVa(va, off)) continue;
                    val = (v.ps == 8) ? Rd64(v.d + off) : Rd32(v.d + off);
                }
            }
            if (!val) continue;
            auto range = stringVaToImage.equal_range(val);
            if (range.first == range.second) continue;
            if (seenModules.count(va)) continue;
            for (auto it = range.first; it != range.second; ++it) {
                // Il2CppCodeGenModule dogrulamasi
                const u32 count = v.ReadU32Va(va + 8, okR);
                if (!okR || count == 0 || count > 5000000) continue;
                const u64 mpVa = v.ReadPtrVa(va + (u64)(v.ps == 8 ? 0x10 : 0xC), okR, frR);
                if (!okR || !mpVa || !v.InAny(mpVa)) continue;
                // ornekleme: ilk 32 metod gostericisi exec'e isaret etmeli
                const u32 sample = std::min<u32>(count, 32);
                u32 execHits = 0, nonNull = 0;
                for (u32 k = 0; k < sample; k++) {
                    bool pok = false, prel = false;
                    const u64 fp = v.ReadPtrVa(mpVa + (u64)k * v.ps, pok, prel);
                    if (!pok) break;
                    if (!fp) continue;
                    nonNull++;
                    if (v.InExec(fp)) execHits++;
                }
                const double ratio = nonNull ? (double)execHits / (double)nonNull : 0.0;
                if (nonNull == 0 || ratio < 0.30) continue;
                Candidate cd;
                cd.imageIndex = it->second;
                cd.moduleVa = va;
                cd.count = count;
                cd.methodPointersVa = mpVa;
                cd.execRatio = ratio;
                candidates.push_back(cd);
                seenModules.insert(va);
                break;
            }
        }
        if (candidates.size() >= 4096) break;
    }

    // ---- image basina en iyi aday ------------------------------------------
    std::vector<u32> imgMethodCount(meta.images.size(), 0);
    for (i32 mi : methodToImage)
        if (mi >= 0 && (u32)mi < imgMethodCount.size()) imgMethodCount[(u32)mi]++;

    std::map<u32, size_t> bestFor;
    for (size_t c = 0; c < candidates.size(); c++) {
        const Candidate& cd = candidates[c];
        auto it = bestFor.find(cd.imageIndex);
        if (it == bestFor.end()) { bestFor[cd.imageIndex] = c; continue; }
        const Candidate& cur = candidates[it->second];
        auto score = [&](const Candidate& x) {
            const i64 diff = (i64)x.count - (i64)imgMethodCount[x.imageIndex];
            return std::llabs(diff) * 100.0 - x.execRatio * 50.0;
        };
        if (score(cd) < score(cur)) bestFor[cd.imageIndex] = c;
    }

    // ---- metod adreslerini coz ---------------------------------------------
    const bool flatMode = out.mode == "flat";
    auto StoreAddress = [&](u32 g, u64 addr, bool fromReloc) {
        Il2MethodAddress ma;
        ma.methodIndex = g;
        ma.va = addr;
        ma.rva = (u32)(addr - v.imageBase);
        u64 fo = 0;
        ma.fileOffset = v.MapVa(addr, fo) ? fo : 0xFFFFFFFFull;
        ma.fromReloc = fromReloc;
        out.methodAddresses[g] = ma;
        out.resolvedCount++;
    };

    if (!flatMode) {
        for (const auto& [im, ci] : bestFor) {
            const Candidate& cd = candidates[ci];
            Il2ModuleMatch mm;
            mm.imageIndex = cd.imageIndex;
            mm.imageName = cd.imageIndex < meta.images.size() ? meta.images[cd.imageIndex].name : "?";
            mm.moduleVa = cd.moduleVa;
            mm.methodPointerCount = cd.count;
            mm.methodPointersVa = cd.methodPointersVa;
            mm.execRatio = cd.execRatio;
            out.modules.push_back(mm);

            for (u32 g = 0; g < meta.methods.size(); g++) {
                if (methodToImage[g] < 0 || (u32)methodToImage[g] != im) continue;
                const Il2MethodInfo& mi = meta.methods[g];
                if ((mi.token >> 24) != 0x06) { out.unresolvedCount++; continue; }
                const u32 rid = mi.token & 0x00FFFFFFu;
                if (rid == 0) { out.unresolvedCount++; continue; }
                const u64 idx = (u64)rid - 1;
                if (idx >= cd.count) { out.unresolvedCount++; continue; }
                bool pok = false, prel = false;
                const u64 addr = v.ReadPtrVa(cd.methodPointersVa + idx * v.ps, pok, prel);
                if (!pok) { out.unresolvedCount++; continue; }
                if (addr == 0) { out.nullCount++; continue; }
                if (!v.InExec(addr)) { out.unresolvedCount++; continue; }
                StoreAddress(g, addr, prel);
            }
        }
    } else {
        // ---- flat mod (v16-24.0): u32 count == metod sayisi + gosterci dizi ----
        const u64 want = meta.methods.size();
        double bestRatio = 0.0;
        u64 bestArrayVa = 0;
        for (const Sec& s : v.secs) {
            if (s.exec) continue;
            if (s.size < 8) continue;
            for (u64 va = s.va; va + v.ps + 8 <= s.va + s.size; va += v.ps) {
                bool cok = false;
                const u32 count = v.ReadU32Va(va, cok);
                if (!cok || count != want) continue;
                bool pok = false, prel = false;
                const u64 arrVa = v.ReadPtrVa(va + (v.ps == 8 ? 8 : 4), pok, prel);
                if (!pok || !arrVa || !v.InAny(arrVa)) continue;
                u32 execHits = 0, nonNull = 0;
                const u32 sampleN = (u32)std::min<u64>(want, 64);
                for (u32 k = 0; k < sampleN; k++) {
                    bool aok = false, arel = false;
                    const u64 fp = v.ReadPtrVa(arrVa + (u64)k * v.ps, aok, arel);
                    if (!aok) break;
                    if (!fp) continue;
                    nonNull++;
                    if (v.InExec(fp)) execHits++;
                }
                const double ratio = nonNull ? (double)execHits / (double)nonNull : 0.0;
                if (ratio > bestRatio) {
                    bestRatio = ratio;
                    bestArrayVa = arrVa;
                }
            }
        }
        if (bestArrayVa && bestRatio >= 0.30) {
            for (u32 g = 0; g < meta.methods.size(); g++) {
                bool aok = false, arel = false;
                const u64 addr = v.ReadPtrVa(bestArrayVa + (u64)g * v.ps, aok, arel);
                if (!aok) { out.unresolvedCount++; continue; }
                if (addr == 0) { out.nullCount++; continue; }
                if (!v.InExec(addr)) { out.unresolvedCount++; continue; }
                StoreAddress(g, addr, arel);
            }
        } else {
            out.lastError = "flat methodPointers kalibi bulunamadi (v16-24.0) veya exec orani cok dusuk";
        }
    }

    // ---- codeGenModules dizisini bul (rapor icin, opsiyonel) ---------------
    if (!out.modules.empty() && out.modules.size() >= 2) {
        const u32 wantCount = (u32)out.modules.size();
        bool found = false;
        for (const Sec& s : v.secs) {
            if (s.exec || found) continue;
            for (u64 va = s.va; va + v.ps + 8 <= s.va + s.size; va += v.ps) {
                bool cok = false;
                const u32 count = v.ReadU32Va(va, cok);
                if (!cok || count != wantCount) continue;
                bool pok = false, prel = false;
                const u64 arrVa = v.ReadPtrVa(va + 8, pok, prel);
                if (!pok || !arrVa || !v.InAny(arrVa)) continue;
                bool all = true;
                for (const Il2ModuleMatch& mm : out.modules) {
                    bool has = false;
                    for (u32 k = 0; k < wantCount; k++) {
                        bool eok = false, erel = false;
                        const u64 mptr = v.ReadPtrVa(arrVa + (u64)k * v.ps, eok, erel);
                        if (eok && mptr == mm.moduleVa) { has = true; break; }
                    }
                    if (!has) { all = false; break; }
                }
                if (all) {
                    out.codeGenModulesArrayVa = arrVa;
                    out.codeGenModulesCount = count;
                    found = true;
                    break;
                }
            }
        }
    }

    // ---- MetadataRegistration taramasi (Il2CppType tablosu) -----------------
    {
        const bool is64 = v.ps == 8;
        const u64 typesCountOff = is64 ? 0x30 : 0x18;
        const u64 typesPtrOff   = is64 ? 0x38 : 0x1C;
        const u64 msCountOff    = is64 ? 0x40 : 0x20;
        const u64 msPtrOff      = is64 ? 0x48 : 0x24;
        const u64 foCountOff    = is64 ? 0x50 : 0x28;
        const u64 foPtrOff      = is64 ? 0x58 : 0x2C;
        // v19+: typeDefinitionsSizes cifti sonrasi metadataUsages cifti
        const u64 usgCountOff   = is64 ? 0x70 : 0x38;
        const u64 usgPtrOff     = is64 ? 0x78 : 0x3C;
        const u64 wantTypeCount = meta.types.size();

        bool found = false;
        for (const Sec& s : v.secs) {
            if (s.exec || found) continue;
            for (u64 va = s.va; va + foPtrOff + v.ps <= s.va + s.size; va += v.ps) {
                bool cok = false;
                const u32 typesCount = v.ReadU32Va(va + typesCountOff, cok);
                if (!cok || typesCount < wantTypeCount || typesCount > 30000000u) continue;
                bool pok = false, prel = false;
                const u64 typesVa = v.ReadPtrVa(va + typesPtrOff, pok, prel);
                if (!pok || !typesVa || !v.InAny(typesVa)) continue;
                u64 arrOff = 0;
                if (!v.MapVa(typesVa, arrOff)) continue;
                if (arrOff + (u64)typesCount * v.ps > v.sz) continue;
                u32 hits = 0;
                const u32 sampleN = std::max<u32>(1u, std::min<u32>(typesCount, 32));
                for (u32 k = 0; k < sampleN; k++) {
                    bool eok = false, erel = false;
                    const u64 tp = v.ReadPtrVa(typesVa + (u64)k * v.ps, eok, erel);
                    if (eok && tp && v.InAny(tp)) hits++;
                }
                if ((double)hits / (double)sampleN < 0.80) continue;
                const u32 foCount = v.ReadU32Va(va + foCountOff, cok);
                if (!cok || foCount != wantTypeCount) continue;
                bool fok = false, frel = false;
                const u64 foVa = v.ReadPtrVa(va + foPtrOff, fok, frel);
                if (!fok || !foVa || !v.InAny(foVa)) continue;

                out.metadataRegistrationFound = true;
                out.metadataRegistrationVa = va;
                out.typesVa = typesVa;
                out.typesCount = typesCount;
                out.fieldOffsetsVa = foVa;
                out.fieldOffsetsCount = foCount;

                // methodSpecs tablosu (MethodRef usage'lari icin)
                bool mok = false;
                const u32 msCount = v.ReadU32Va(va + msCountOff, mok);
                if (mok && msCount > 0 && msCount < 20000000u) {
                    bool mpok = false, mprel = false;
                    const u64 msVa = v.ReadPtrVa(va + msPtrOff, mpok, mprel);
                    if (mpok && msVa && v.InAny(msVa)) {
                        out.methodSpecsVa = msVa;
                        out.methodSpecsCount = msCount;
                    }
                }

                // metadataUsages (v19..24.5): kodgen global hucre dizisi.
                // KATI dogrulama: binary struct count == metadata usage slot sayisi.
                if (meta.hasUsages) {
                    bool uok = false;
                    const u32 usgCount = v.ReadU32Va(va + usgCountOff, uok);
                    if (uok && usgCount == meta.usageSlotCount) {
                        bool upok = false, uprel = false;
                        const u64 usgVa = v.ReadPtrVa(va + usgPtrOff, upok, uprel);
                        if (upok && usgVa && v.InAny(usgVa)) {
                            out.usagesFound = true;
                            out.usagesVa = usgVa;
                            out.usagesCountBinary = usgCount;
                        }
                    }
                }
                found = true;
                break;
            }
        }
        out.typesResolved = found;
    }

    // ---- alan ofsetleri (dump.cs yorumlari icin) ----------------------------
    if (out.typesResolved && out.fieldOffsetsVa) {
        for (u32 ti = 0; ti < meta.types.size() && ti < out.fieldOffsetsCount; ti++) {
            bool pok = false, prel = false;
            const u64 foArrVa = v.ReadPtrVa(out.fieldOffsetsVa + (u64)ti * v.ps, pok, prel);
            if (!pok || !foArrVa || !v.InAny(foArrVa)) continue;
            const Il2TypeInfo& ty = meta.types[ti];
            if (ty.fieldCount == 0) continue;
            std::vector<i32> ofs(ty.fieldCount, -1);
            bool any = false;
            for (u32 k = 0; k < ty.fieldCount; k++) {
                bool iok = false;
                const u32 raw = v.ReadU32Va(foArrVa + (u64)k * 4, iok);
                if (!iok) break;
                const i32 val = (i32)raw;
                if (val <= 0 || val > 0xFFFFFF) { ofs[k] = -1; continue; } // static/pad
                ofs[k] = val;
                any = true;
            }
            if (any) out.fieldOffsets[ti] = std::move(ofs);
        }
    }

    // ---- metadataUsages slot cozumleme (v19..24.5) --------------------------
    // Her pair: metadataUsages[destinationIndex] hucresinin DEGERI kodgen
    // global hucrenin VA'sidir (g_MyClass_TypeInfo gibi); usage tipine gore
    // o hucreye baglanacak metadata kaydi isimlendirilir. Hucre cogunlukla
    // .bss'te yasar -> InDataCell (map'li VEYA bss) ile dogrulanir.
    if (out.usagesFound && !meta.usages.empty()) {
        TypeResolver res(v, meta);
        std::unordered_set<u64> visited;

        // FieldInfo isimleri icin: cozulen tip adini metadata tam adina
        // eslestiren harita (yalnizca fieldRef kullanildiginda kurulur)
        std::unordered_map<std::string, u32> metaTypeByName;
        const bool needFieldNames = !meta.usageFieldRefs.empty();
        if (needFieldNames) {
            for (u32 ti = 0; ti < meta.types.size(); ti++) {
                const Il2TypeInfo& ty = meta.types[ti];
                std::string full = ty.ns.empty() ? ty.name : ty.ns + "." + ty.name;
                if (!full.empty()) metaTypeByName.emplace(std::move(full), ti);
            }
        }

        auto TypeNameViaResolver = [&](i32 typeIdx) -> std::string {
            if (!out.typesResolved || !out.typesVa) return "T<" + std::to_string(typeIdx) + ">";
            bool pok = false, prel = false;
            const u64 tp = v.ReadPtrVa(out.typesVa + (u64)typeIdx * v.ps, pok, prel);
            if (!pok || !tp) return "T<" + std::to_string(typeIdx) + ">";
            std::unordered_set<u64> seen;
            std::string s = res.Resolve(tp, seen);
            return s.empty() || s == "?" ? "T<" + std::to_string(typeIdx) + ">" : s;
        };

        out.usageSlots.reserve(meta.usages.size());
        for (const Il2UsagePair& up : meta.usages) {
            Il2UsageSlot slot;
            slot.destinationIndex = up.destinationIndex;
            slot.usageType = up.usageType;
            slot.decodedIndex = up.decodedIndex;

            // dizideki slotun DEGERI = kodgen global hucre VA (reloc-aware)
            bool sok = false, srel = false;
            const u64 cellVa = v.ReadPtrVa(out.usagesVa + (u64)up.destinationIndex * v.ps, sok, srel);
            slot.cellVa = cellVa;
            slot.resolved = sok && cellVa != 0 && v.InDataCell(cellVa);

            char fb[64];
            switch (up.usageType) {
                case 1: { // TypeInfo: metadata TypeDefinition indexi
                    if (up.decodedIndex < meta.types.size()) {
                        const Il2TypeInfo& ty = meta.types[up.decodedIndex];
                        slot.name = ty.ns.empty() ? ty.name : ty.ns + "." + ty.name;
                    }
                    break;
                }
                case 2: { // Il2CppType: binary Il2CppType tablosu indexi
                    slot.name = TypeNameViaResolver((i32)up.decodedIndex);
                    break;
                }
                case 3: { // MethodDef: metadata metod indexi
                    if (up.decodedIndex < meta.methods.size()) {
                        const Il2MethodInfo& mi = meta.methods[up.decodedIndex];
                        const i32 ti = TypeOfMethod(meta, up.decodedIndex);
                        std::string tn = (ti >= 0 && (u32)ti < meta.types.size())
                            ? (meta.types[ti].ns.empty() ? meta.types[ti].name
                                                         : meta.types[ti].ns + "." + meta.types[ti].name)
                            : "?";
                        slot.name = tn + "::" + mi.name;
                    }
                    break;
                }
                case 4: { // FieldInfo: fieldRefs indexi (typeIndex = Il2CppType idx)
                    auto fit = meta.usageFieldRefs.find(up.decodedIndex);
                    if (fit != meta.usageFieldRefs.end()) {
                        std::string tn = TypeNameViaResolver(fit->second.typeIndex);
                        std::string fieldName;
                        auto tit = needFieldNames ? metaTypeByName.find(tn) : metaTypeByName.end();
                        if (tit != metaTypeByName.end()) {
                            const Il2TypeInfo& ty = meta.types[tit->second];
                            const u64 local = (u64)std::max(fit->second.fieldIndex, 0);
                            const u64 gi = (u64)ty.fieldStart + local;
                            if (local < ty.fieldCount && gi < meta.fields.size())
                                fieldName = meta.fields[gi].name;
                        }
                        slot.name = tn + "." + (fieldName.empty()
                                     ? ("fieldRef#" + std::to_string(up.decodedIndex))
                                     : fieldName);
                    } else {
                        snprintf(fb, sizeof(fb), "fieldRef#%u", up.decodedIndex);
                        slot.name = fb;
                    }
                    break;
                }
                case 5: { // StringLiteral: metadata literal indexi
                    auto lit = meta.usageStringLiterals.find(up.decodedIndex);
                    slot.name = (lit != meta.usageStringLiterals.end())
                                ? lit->second : ("<literal#" + std::to_string(up.decodedIndex) + ">");
                    break;
                }
                case 6: { // MethodRef: binary Il2CppMethodSpec indexi
                    // Il2CppMethodSpec { i32 methodDefinitionIndex; i32 classIdxIdx; i32 methodIdxIdx; } (12B)
                    if (out.methodSpecsVa && up.decodedIndex < out.methodSpecsCount) {
                        u64 mOff = 0;
                        if (v.MapVa(out.methodSpecsVa + (u64)up.decodedIndex * 12, mOff) &&
                            mOff + 12 <= v.sz) {
                            const i32 mDefIdx = (i32)Rd32(v.d + mOff);
                            if (mDefIdx >= 0 && (u32)mDefIdx < meta.methods.size()) {
                                const Il2MethodInfo& mi = meta.methods[(u32)mDefIdx];
                                const i32 ti = TypeOfMethod(meta, (u32)mDefIdx);
                                std::string tn = (ti >= 0 && (u32)ti < meta.types.size())
                                    ? (meta.types[ti].ns.empty() ? meta.types[ti].name
                                                                 : meta.types[ti].ns + "." + meta.types[ti].name)
                                    : "?";
                                slot.name = tn + "::" + mi.name + "()";
                            }
                        }
                    }
                    if (slot.name.empty())
                        slot.name = "methodSpec#" + std::to_string(up.decodedIndex);
                    break;
                }
                default:
                    slot.name = "<bilinmeyen usage tipi>";
                    break;
            }
            out.usageSlots.push_back(std::move(slot));
        }

        u32 nResolved = 0;
        for (const Il2UsageSlot& s : out.usageSlots) if (s.resolved) nResolved++;
        Log::Info("metadataUsages: %u slot (%u hucre dogrulandi)", out.usageSlots.size(), nResolved);
    }

    out.valid = out.resolvedCount > 0;
    if (!out.valid && out.lastError.empty())
        out.lastError = "hicbir metod adresi cozulemedi";
    return out.valid;
}

// ============================================================================
// cikti uretimi
// ============================================================================

std::string Il2CppBinaryMatch::BuildDumpCsBinary(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                                 const u8* binData, size_t binSize) {
    std::string o;
    o.reserve(6 << 20);
    o += "// DumperPro IL2CPP dump.cs (binary eslestirmeli)\n";
    o += "// metadata surumu: " + meta.versionStr +
         (meta.unityHint.empty() ? "" : "  (" + meta.unityHint + ")") + "\n";
    o += "// binary format   : " + bin.format + " " + std::to_string(bin.bits) + "-bit " + bin.arch + "\n";
    o += "// cozulen metod   : " + std::to_string(bin.resolvedCount) + " / " +
         std::to_string(meta.methods.size()) + "\n";
    if (bin.typesResolved)
        o += "// Il2CppType tablosu cozuldu: gercek tip isimleri ve alan ofsetleri kullanilir\n";
    else
        o += "// NOT: MetadataRegistration bulunamadi - bilinmeyen tipler T<idx> olarak yazilir\n";
    o += "\n";

    // tip cozumu icin BinaryView'i yeniden kur (Match ile ayni gecis)
    BinaryView v;
    std::string archTmp;
    if (binData && binSize) BuildAnyView(binData, binSize, v, archTmp);

    TypeResolver res(v, meta);
    std::unordered_set<u64> visited;
    const BinaryView* vp = (binData && binSize) ? &v : nullptr;
    auto TypeName = [&](i32 typeIndex) -> std::string {
        return ResolveTypeIdx(vp, &bin, meta, typeIndex, visited, res);
    };

    for (size_t i = 0; i < meta.types.size(); i++) {
        const Il2TypeInfo& t = meta.types[i];
        o += "// TypeDefinition #" + std::to_string(i) + "  token=" + HexT(t.token) + "\n";
        if (!t.ns.empty()) o += "namespace " + t.ns + "\n{\n";
        o += ModifiersOf2(t) + " " + KindOf2(t) + " " + (t.name.empty() ? "<anon>" : t.name) + "\n{\n";

        auto fit = bin.fieldOffsets.find((u32)i);
        for (u32 k = 0; k < t.fieldCount && (u64)t.fieldStart + k < meta.fields.size(); k++) {
            const Il2FieldInfo& f = meta.fields[t.fieldStart + k];
            std::string offCmt;
            if (fit != bin.fieldOffsets.end() && k < fit->second.size() && fit->second[k] > 0) {
                char b[32];
                snprintf(b, sizeof(b), " // 0x%02X", fit->second[k]);
                offCmt = b;
            }
            o += "    " + FieldAccess2(f.flags) + (f.flags & 0x10u ? " static" : "") +
                 " " + TypeName(f.typeIndex) + " " +
                 (f.name.empty() ? "<field>" : f.name) + ";" + offCmt + "\n";
        }
        for (u32 k = 0; k < t.methodCount && (u64)t.methodStart + k < meta.methods.size(); k++) {
            const u32 g = t.methodStart + k;
            const Il2MethodInfo& mi = meta.methods[g];
            o += "    " + MethodAccess2(mi.flags) +
                 (mi.flags & 0x10u ? " static" : "") +
                 (mi.flags & 0x40u ? " virtual" : "") +
                 (mi.flags & 0x400u ? " abstract" : "") +
                 " " + TypeName(mi.returnTypeIndex) + " " +
                 (mi.name.empty() ? "<method>" : mi.name) + "(";
            for (u32 p = 0; p < mi.parameterCount; p++) {
                const u64 pi = (u64)mi.parameterStart + p;
                if (pi < meta.params.size()) {
                    if (p) o += ", ";
                    o += TypeName(meta.params[pi].typeIndex) + " " +
                         (meta.params[pi].name.empty() ? "<p>" : meta.params[pi].name);
                }
            }
            o += "); // slot=" + std::to_string(mi.slot);
            auto ait = bin.methodAddresses.find(g);
            if (ait != bin.methodAddresses.end()) {
                char rb[32], vb[32], ob[32];
                snprintf(rb, sizeof(rb), "0x%X", ait->second.rva);
                snprintf(vb, sizeof(vb), "0x%llX", (unsigned long long)ait->second.va);
                snprintf(ob, sizeof(ob), "0x%llX", (unsigned long long)ait->second.fileOffset);
                o += std::string("  // RVA: ") + rb + " Offset: " + ob + " VA: " + vb;
            } else if (bin.resolvedCount > 0) {
                o += "  // RVA: 0x0 (govde yok)";
            }
            o += "\n";
        }
        o += "}\n";
        if (!t.ns.empty()) o += "}\n";
        o += "\n";
    }
    return o;
}

std::string Il2CppBinaryMatch::BuildScriptJson(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                               const u8* binData, size_t binSize) {
    // Il2CppDumper script.json semasi:
    //   ScriptMethod         [{Name, Address}]
    //   ScriptString         [{Address, Value}]        (StringLiteral usage'lari)
    //   ScriptMetadata       [{Address, Name, Signature}] (TypeInfo/Il2CppType/FieldInfo)
    //   ScriptMetadataMethod [{Address, Name, MethodAddress}] (MethodDef/MethodRef)
    // Adresler: DumperPro konvansiyonu = VA (PE: ImageBase dahil, ELF PIE: RVA'ya esdeger)
    std::string j;
    j.reserve(4 << 20);
    j += "{\n  \"ScriptMethod\": [\n";
    bool first = true;
    std::vector<std::string> typeFull(meta.types.size());
    for (size_t i = 0; i < meta.types.size(); i++) {
        const Il2TypeInfo& t = meta.types[i];
        typeFull[i] = t.ns.empty() ? t.name : t.ns + "." + t.name;
        if (typeFull[i].empty()) typeFull[i] = "<anon_" + std::to_string(i) + ">";
    }
    for (size_t i = 0; i < meta.types.size(); i++) {
        const Il2TypeInfo& t = meta.types[i];
        for (u32 k = 0; k < t.methodCount && (u64)t.methodStart + k < meta.methods.size(); k++) {
            const u32 g = t.methodStart + k;
            auto it = bin.methodAddresses.find(g);
            if (it == bin.methodAddresses.end()) continue;
            const Il2MethodInfo& mi = meta.methods[g];
            const std::string full = typeFull[i] + "::" +
                                     (mi.name.empty() ? "<method>" : mi.name);
            if (!first) j += ",\n";
            first = false;
            j += "    {\"Name\": \"" + JsonEsc2(full) + "\", \"Address\": " +
                 std::to_string(it->second.va) + "}";
        }
    }
    j += "\n  ],\n";

    // ---- ScriptString / ScriptMetadata / ScriptMetadataMethod (usages) ------
    // Isimler Match() icinde zaten cozuldu (slot.name); burada yalnizca JSON'a
    // yazilir. Adres = kodgen global hucre VA.
    std::string strJ, metaJ, metaMethJ;
    bool sFirst = true, mFirst = true, mmFirst = true;
    if (bin.usagesFound) {
        for (const Il2UsageSlot& s : bin.usageSlots) {
            if (!s.resolved) continue;
            const std::string addr = std::to_string(s.cellVa);
            switch (s.usageType) {
                case 1: // TypeInfo -> ScriptMetadata (Il2CppDumper: <Tip>_TypeInfo / Il2CppClass*)
                    if (!mFirst) metaJ += ",\n";
                    mFirst = false;
                    metaJ += "    {\"Address\": " + addr + ", \"Name\": \"" +
                             JsonEsc2(s.name + "_TypeInfo") + "\", \"Signature\": \"Il2CppClass*\"}";
                    break;
                case 2: // Il2CppType -> ScriptMetadata (<Tip>_var / Il2CppType*)
                    if (!mFirst) metaJ += ",\n";
                    mFirst = false;
                    metaJ += "    {\"Address\": " + addr + ", \"Name\": \"" +
                             JsonEsc2(s.name + "_var") + "\", \"Signature\": \"Il2CppType*\"}";
                    break;
                case 3: { // MethodDef -> ScriptMetadataMethod (Method$Tip::Metod)
                    auto ait = bin.methodAddresses.find(s.decodedIndex);
                    metaMethJ += mmFirst ? "" : ",\n";
                    mmFirst = false;
                    metaMethJ += "    {\"Address\": " + addr + ", \"Name\": \"Method$" +
                                 JsonEsc2(s.name) + "\", \"MethodAddress\": " +
                                 (ait != bin.methodAddresses.end() ? std::to_string(ait->second.va) : "0") + "}";
                    break;
                }
                case 4: // FieldInfo -> ScriptMetadata (<Tip>.<alan> / FieldInfo*)
                    if (!mFirst) metaJ += ",\n";
                    mFirst = false;
                    metaJ += "    {\"Address\": " + addr + ", \"Name\": \"" +
                             JsonEsc2(s.name) + "\", \"Signature\": \"FieldInfo*\"}";
                    break;
                case 5: // StringLiteral -> ScriptString (deger)
                    if (!sFirst) strJ += ",\n";
                    sFirst = false;
                    strJ += "    {\"Address\": " + addr + ", \"Value\": \"" + JsonEsc2(s.name) + "\"}";
                    break;
                case 6: // MethodRef -> ScriptMetadataMethod (MethodSpec uzerinden)
                    metaMethJ += mmFirst ? "" : ",\n";
                    mmFirst = false;
                    metaMethJ += "    {\"Address\": " + addr + ", \"Name\": \"Method$" +
                                 JsonEsc2(s.name) + "\", \"MethodAddress\": 0}";
                    break;
                default:
                    break;
            }
        }
    }

    j += "  \"ScriptString\": [\n" + strJ + (strJ.empty() ? "" : "\n") + "  ],\n";
    j += "  \"ScriptMetadata\": [\n" + metaJ + (metaJ.empty() ? "" : "\n") + "  ],\n";
    j += "  \"ScriptMetadataMethod\": [\n" + metaMethJ + (metaMethJ.empty() ? "" : "\n") + "  ],\n";
    j += "  \"Addresses\": [],\n";
    j += "  \"_comment\": \"DumperPro il2cpp script.json (Il2CppDumper uyumlu; Address = PE VA / ELF PIE VA; ScriptMetadata v19-24.5 usage slotlari)\"\n";
    j += "}\n";
    return j;
}

std::string Il2CppBinaryMatch::BuildUsagesTxt(const Il2Metadata& meta, const Il2BinaryResult& bin) {
    std::vector<std::string> L;
    L.push_back("; DumperPro - IL2CPP metadata usage slotlari (v19-24.5)");
    L.push_back("; Slot = kodgen global hucre VA (runtime calisirca gercek gostericilerle doldurulur)");
    L.push_back("; Tip  : 1=TypeInfo 2=Il2CppType 3=MethodDef 4=FieldInfo 5=StringLiteral 6=MethodRef");
    L.push_back("; Kaynak: Il2CppDumper StructGenerator.cs AddMetadataUsage* semantigi");
    if (!bin.usagesFound) {
        L.push_back("; (bu binary/metadata ciftinde usage tablosu yok - v19..24.5 gereklidir)");
        return str::Join(L, "\n") + "\n";
    }
    L.push_back("");
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "%-8s %-4s %-10s %-18s %-9s %s",
             "Slot", "Tip", "Index", "HucreVA", "Durum", "Referans");
    L.push_back(hdr);
    L.push_back(std::string(110, '-'));

    static const char* kTypeNames[7] = {"", "TypeInfo", "Il2CppType", "MethodDef",
                                        "FieldInfo", "StringLiteral", "MethodRef"};
    u32 unresolved = 0;
    for (const Il2UsageSlot& s : bin.usageSlots) {
        char b[512];
        const char* tn = (s.usageType <= 6) ? kTypeNames[s.usageType] : "?";
        if (!s.resolved) unresolved++;
        std::string name = s.name;
        // tek satir guvencesi
        for (char& c : name) if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (name.size() > 100) name = name.substr(0, 100) + "...";
        snprintf(b, sizeof(b), "%-8u %-4s %-10u %-18s %-9s %s",
                 s.destinationIndex, tn, s.decodedIndex,
                 Hex(s.cellVa).c_str(),
                 s.resolved ? "OK" : "COZULEMEDI",
                 name.c_str());
        L.push_back(b);
    }
    L.push_back("");
    L.push_back("Toplam: " + std::to_string(bin.usageSlots.size()) +
                " slot, dogrulanan hucre: " +
                std::to_string(bin.usageSlots.size() - unresolved) +
                ", cozulemeyen: " + std::to_string(unresolved));
    L.push_back("Yasal sinir: yalnizca sahibi olunan/lisansli yazilimin analizi.");
    return str::Join(L, "\n") + "\n";
}

std::string Il2CppBinaryMatch::BuildMethodAddressesTxt(const Il2Metadata& meta, const Il2BinaryResult& bin) {
    std::vector<std::string> L;
    L.push_back("; DumperPro - IL2CPP metod adresleri (binary eslestirmesi)");
    L.push_back("; binary  : " + bin.format + " " + std::to_string(bin.bits) + "-bit " + bin.arch +
                (bin.imageBase ? "  imageBase=" + Hex(bin.imageBase) : "  (PIE, base 0)"));
    L.push_back("; metadata: surum " + bin.metadataVersion);
    L.push_back("; format  : RVA | VA | Offset | Image | Tip | Metod | token");
    L.push_back("");

    std::vector<std::string> typeFull(meta.types.size());
    for (size_t i = 0; i < meta.types.size(); i++) {
        const Il2TypeInfo& t = meta.types[i];
        typeFull[i] = t.ns.empty() ? t.name : t.ns + "." + t.name;
        if (typeFull[i].empty()) typeFull[i] = "<anon_" + std::to_string(i) + ">";
    }

    std::vector<std::pair<u32, const Il2MethodAddress*>> sorted;
    sorted.reserve(bin.methodAddresses.size());
    for (const auto& [g, ma] : bin.methodAddresses) sorted.emplace_back(g, &ma);
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    char line[512];
    for (const auto& [g, ma] : sorted) {
        const Il2MethodInfo& mi = meta.methods[g];
        std::string img = "<bilinmiyor>";
        const i32 ti = TypeOfMethod(meta, g);
        std::string typ = ti >= 0 ? typeFull[(size_t)ti] : "<bilinmiyor>";
        if (ti >= 0) {
            for (const Il2ImageInfo& im2 : meta.images) {
                if ((u32)ti >= im2.typeStart && (u32)ti < im2.typeStart + im2.typeCount) {
                    img = im2.name;
                    break;
                }
            }
        }
        char rb[32], vb[32], ob[32], tkb[16];
        snprintf(rb, sizeof(rb), "0x%X", ma->rva);
        snprintf(vb, sizeof(vb), "0x%llX", (unsigned long long)ma->va);
        if (ma->fileOffset == 0xFFFFFFFFull) snprintf(ob, sizeof(ob), "?");
        else snprintf(ob, sizeof(ob), "0x%llX", (unsigned long long)ma->fileOffset);
        snprintf(tkb, sizeof(tkb), "0x%08X", mi.token);
        snprintf(line, sizeof(line), "%-10s %-14s %-14s %-28s %-52s %-40s %s%s",
                 rb, vb, ob,
                 img.substr(0, 28).c_str(),
                 typ.substr(0, 52).c_str(),
                 mi.name.substr(0, 40).c_str(),
                 tkb,
                 ma->fromReloc ? " [reloc]" : "");
        L.push_back(line);
    }

    if (sorted.empty()) L.push_back("(adres cozulen metod yok)");
    return str::Join(L, "\n") + "\n";
}

std::string Il2CppBinaryMatch::BuildBinaryReport(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                                 const std::string& binName, const std::string& metaName) {
    std::vector<std::string> L;
    auto H = [&](const std::string& t) {
        std::string line(64, '=');
        L.push_back(line); L.push_back(t); L.push_back(line);
    };

    H("DumperPro - IL2CPP Binary Eslestirme Raporu");
    L.push_back("Binary          : " + binName);
    L.push_back("Metadata        : " + metaName);
    L.push_back("Binary format   : " + bin.format + " " + std::to_string(bin.bits) + "-bit " + bin.arch +
                (bin.imageBase ? "  imageBase=" + Hex(bin.imageBase) : "  (PIE, base 0)"));
    L.push_back("Metadata surumu : " + bin.metadataVersion);
    L.push_back("Tarama modu     : " + bin.mode);
    L.push_back("");
    L.push_back("Durum           : " + std::string(bin.valid ? "BASARILI" : "ESLESME YOK: " + bin.lastError));
    L.push_back("Cozulen metod   : " + std::to_string(bin.resolvedCount) + " / " +
                std::to_string(meta.methods.size()) +
                "  (govdesiz: " + std::to_string(bin.nullCount) +
                ", cozulemeyen: " + std::to_string(bin.unresolvedCount) + ")");
    L.push_back("");

    H("IL2CPP CODEGEN MODULES");
    if (bin.modules.empty()) {
        L.push_back("  (bulunamadi - image isimleri binary'de eslesmedi)");
    } else {
        L.push_back("Bulunan modul sayisi : " + std::to_string(bin.modules.size()) + " / " +
                    std::to_string(meta.images.size()));
        if (bin.codeGenModulesArrayVa)
            L.push_back("codeGenModules dizisi: VA " + Hex(bin.codeGenModulesArrayVa) +
                        "  (count=" + std::to_string(bin.codeGenModulesCount) + ")");
        L.push_back("");
        const size_t cap = std::min<size_t>(bin.modules.size(), 40);
        for (size_t i = 0; i < cap; i++) {
            const Il2ModuleMatch& m = bin.modules[i];
            char b[256];
            snprintf(b, sizeof(b), "  %-34s count=%-7u methodPointers=%-14s exec=%.0f%%",
                     m.imageName.substr(0, 34).c_str(), m.methodPointerCount,
                     Hex(m.methodPointersVa).c_str(), m.execRatio * 100.0);
            L.push_back(b);
        }
        if (bin.modules.size() > cap)
            L.push_back("  ... (+" + std::to_string(bin.modules.size() - cap) + " daha)");
    }
    L.push_back("");

    H("METADATA REGISTRATION (Il2CppType tablosu)");
    if (bin.metadataRegistrationFound) {
        L.push_back("Durum             : BULUNDU (fieldOffsetsCount == tip sayisi dogrulandi)");
        L.push_back("MetadataReg VA    : " + Hex(bin.metadataRegistrationVa));
        L.push_back("Il2CppType dizisi : VA " + Hex(bin.typesVa) + "  count=" + std::to_string(bin.typesCount));
        L.push_back("fieldOffsets      : VA " + Hex(bin.fieldOffsetsVa) +
                    "  count=" + std::to_string(bin.fieldOffsetsCount));
        if (bin.methodSpecsVa)
            L.push_back("methodSpecs       : VA " + Hex(bin.methodSpecsVa) +
                        "  count=" + std::to_string(bin.methodSpecsCount));
        L.push_back("Sonuc             : dump.cs ciktisinda GERCEK tip isimleri + alan ofsetleri var");
    } else {
        L.push_back("Durum : bulunamadi (bilinmeyen tipler T<idx> olarak kalir)");
    }
    L.push_back("");

    H("METADATA USAGES (kodgen global hucre eslestirmesi, v19-24.5)");
    if (bin.usagesFound) {
        u32 nOk = 0;
        for (const Il2UsageSlot& s : bin.usageSlots) if (s.resolved) nOk++;
        L.push_back("Durum          : BULUNDU (binary count " + std::to_string(bin.usagesCountBinary) +
                    " == metadata slot sayisi dogrulandi)");
        L.push_back("usages dizisi  : VA " + Hex(bin.usagesVa));
        L.push_back("Slot sayisi    : " + std::to_string(bin.usageSlots.size()) +
                    "  (hucre dogrulanan: " + std::to_string(nOk) + ")");
        u32 byType[7] = {0, 0, 0, 0, 0, 0, 0};
        for (const Il2UsageSlot& s : bin.usageSlots)
            if (s.usageType <= 6) byType[s.usageType]++;
        L.push_back("Dagilim        : TypeInfo=" + std::to_string(byType[1]) +
                    "  Il2CppType=" + std::to_string(byType[2]) +
                    "  MethodDef=" + std::to_string(byType[3]) +
                    "  FieldInfo=" + std::to_string(byType[4]) +
                    "  StringLiteral=" + std::to_string(byType[5]) +
                    "  MethodRef=" + std::to_string(byType[6]));
        L.push_back("Sonuc          : il2cpp_usages.txt + script.json ScriptMetadata bolumleri dolu");
    } else {
        L.push_back("Durum : yok (yalnizca metadata v19-24.5'te tablo vardir; v25+ build'lerde kaldirildi)");
    }
    L.push_back("");

    H("NOTLAR");
    L.push_back("  - Adresler image-gorelidir: PE icin RVA=VA-ImageBase; ELF PIE icin VA==RVA.");
    L.push_back("  - il2cpp_script.json IDA/Ghidra script girdileri icerir (Il2CppDumper uyumlu).");
    L.push_back("  - methodPointers[RID-1]==0 govdesiz metod demektir (abstract/extern).");
    L.push_back("  - Yasal sinir: yalnizca sahibi olunan/lisansli yazilimin analizi.");
    return str::Join(L, "\n") + "\n";
}

void Il2CppBinaryMatch::WriteOutputs(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                     const fs::path& outDir,
                                     const std::string& binName, const std::string& metaName,
                                     const u8* binData, size_t binSize) {
    std::error_code ec;
    fs::create_directories(outDir, ec);

    {
        std::ofstream f(outDir / "il2cpp_dump.cs", std::ios::binary | std::ios::trunc);
        f << BuildDumpCsBinary(meta, bin, binData, binSize);
    }
    {
        std::ofstream f(outDir / "il2cpp_methodaddresses.txt", std::ios::binary | std::ios::trunc);
        f << BuildMethodAddressesTxt(meta, bin);
    }
    {
        std::ofstream f(outDir / "il2cpp_script.json", std::ios::binary | std::ios::trunc);
        f << BuildScriptJson(meta, bin, binData, binSize);
    }
    {
        std::ofstream f(outDir / "il2cpp_usages.txt", std::ios::binary | std::ios::trunc);
        f << BuildUsagesTxt(meta, bin);
    }
    {
        std::ofstream f(outDir / "il2cpp_binary_report.txt", std::ios::binary | std::ios::trunc);
        f << BuildBinaryReport(meta, bin, binName, metaName);
    }
    Log::Ok("IL2CPP binary outputs -> %s", outDir.string().c_str());
}

std::string Il2CppBinaryMatch::ResolveTypeCSharpName(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                                     const u8* binData, size_t binSize, i32 typeIndex) {
    if (typeIndex < 0) return "object";
    BinaryView v;
    std::string archTmp;
    const bool haveView = (binData && binSize) && BuildAnyView(binData, binSize, v, archTmp);
    TypeResolver res(v, meta);
    std::unordered_set<u64> visited;
    return ResolveTypeIdx(haveView ? &v : nullptr, &bin, meta, typeIndex, visited, res);
}

} // namespace dumper
