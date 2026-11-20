// ============================================================================
// DumperPro - UniFormat.h
//
// Portable binary format helpers:
//   - ELF (32/64, LE/BE) header + section table  (TIS ELF / System V ABI spec)
//   - DEX header + counts                        (AOSP dex-format.md)
//   - UE version string scan ("++UE4+Release-4.27-0.0", "++UE5+Release-5.3.2")
//
// No external dependency, no windows.h - compiles everywhere C++20 does.
// ============================================================================
#pragma once
#include "../framework.h"

namespace dumper {

struct ElfSection {
    std::string name;
    std::string typeName;
    u64 addr = 0;              // sanal adres (PIE'da image-base goreli)
    u64 offset = 0;            // DOSYADAKI raw ofset (sh_offset)
    u64 size = 0;
    u32 flags = 0;             // sh_flags (exec/writable/alloc tespiti icin)
    bool exec = false;         // SHF_EXECINSTR
    bool write = false;        // SHF_WRITE
    bool alloc = false;        // SHF_ALLOC
};

struct ElfInfo {
    bool valid = false;
    int bits = 0;              // 32 | 64
    std::string endian;        // LE | BE
    std::string machine;       // "x86-64", "AArch64", "ARM", ...
    std::string type;          // "EXEC", "DYN", "REL", "CORE"
    u64 entryPoint = 0;
    u32 sectionCount = 0;
    std::vector<ElfSection> sections; // cap 64
};

// minimal DEX facts (counts only; string scan stays in StaticAnalyzer)
struct DexInfo {
    bool valid = false;
    std::string version;   // "035".."039"
    u32 stringIdsSize = 0, typeIdsSize = 0, protoIdsSize = 0;
    u32 fieldIdsSize = 0, methodIdsSize = 0, classDefsSize = 0;
};

struct UeVersionHit {
    std::string raw;     // "++UE5+Release-5.3.2-0.0"
    std::string version; // "5.3.2"
};

// --- yeni arama/cikarma veri tipleri ---------------------------------------
// ELF dynamic symbol (.dynsym) kaydi
struct ElfDynSym {
    std::string name;
    std::string type;     // FUNC | OBJECT | ...
    std::string bind;     // GLOBAL | WEAK | LOCAL
    u64 value = 0;        // sanal adres
    u64 size = 0;
};

// DEX string havuzu sonuclari (MUTF-8 cozumlu)
struct DexStrings {
    u32 totalStrings = 0;             // string_ids_size
    std::vector<std::string> sample;  // ilk N string (cap)
    std::vector<std::string> hints;   // motor/paket ipucu stringleri (com.*, unity, ...)
    u32 decoded = 0;                  // cozulen string sayisi (cap uzeri sayilir)
};

class UniFormat {
public:
    static bool ParseElf(const u8* d, size_t sz, ElfInfo& out);
    static bool ParseDex(const u8* d, size_t sz, DexInfo& out);

    // --- yeni: dynamic symbol tablosu (.dynsym + .dynstr) ---
    // elf.sections'dan DYNSYM bolumunu kullanir; out.exports = GLOBAL/WEAK
    // FUNC/OBJECT sembolleri (cap). Dondurulen deger: toplam dynsym girdisi.
    static u32 ParseElfDynSym(const u8* d, size_t sz, const ElfInfo& elf,
                              std::vector<ElfDynSym>& out, size_t cap = 128);

    // --- yeni: DEX string havuzu (string_data_item + MUTF-8) ---
    static bool ParseDexStrings(const u8* d, size_t sz, DexStrings& out,
                                size_t sampleCap = 40, size_t scanCap = 4096);

    // scan a buffer for UE build markers ("++UE4+Release-4.27-0.0", ...)
    static std::vector<UeVersionHit> UeVersionStrings(const u8* d, size_t sz, size_t cap = 16);

    // format sniff (PE/ELF/DEX/ZIP/OAT/VDEX/CDEX/IL2CPP-metadata/Mach-O/FAT/unknown)
    // using magic bytes
    static std::string SniffMagic(const u8* d, size_t sz);
};

} // namespace dumper
