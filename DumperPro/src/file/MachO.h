// ============================================================================
// DumperPro - MachO.h
//
// Portable Mach-O (32/64) + FAT (universal binary) parser.
// Kaynak: Apple Mach-O format docs / LLVM MachO.h / Apple ABI notes.
//   - MH_MAGIC  0xFEEDFACE / MH_CIGAM  0xCEFAEDFE (32-bit)
//   - MH_MAGIC_64 0xFEEDFACF / MH_CIGAM_64 0xCFFAEDFE (64-bit)
//   - FAT_MAGIC 0xCAFEBABE (BE) / FAT_MAGIC_64 0xCAFEBABF
// Load commands (temel set):
//   LC_SEGMENT/LC_SEGMENT_64, LC_UUID, LC_SYMTAB (sayim + ornek),
//   LC_DYLD_INFO(_ONLY) export, LC_BUILD_VERSION, LC_VERSION_MIN_*,
//   LC_MAIN (entry), LC_SOURCE_VERSION.
// No external dependency, no windows.h - compiles everywhere C++20 does.
// ============================================================================
#pragma once
#include "../framework.h"

namespace dumper {

struct MachOSection {
    std::string name;
    std::string segment;
    u64 addr = 0;
    u64 size = 0;
    u32 offset = 0;          // dosyadaki raw ofset
    u32 flags = 0;
    bool exec = false;
    bool write = false;
};

struct MachOFatArch {
    u32 cputype = 0, cpusubtype = 0;
    u64 offset = 0, size = 0;
    std::string cpuName;
    std::string platName;    // biliniyorsa
};

struct MachOInfo {
    bool valid = false;
    std::string lastError;

    int bits = 0;                       // 32 | 64
    std::string endian;                 // LE | BE (yazilisa gore)
    std::string cpu;                    // "x86-64", "ARM64", "ARM", "x86" ...
    std::string fileType;               // EXECUTE | DYLIB | BUNDLE | OBJECT | CORE
    u32 flags = 0;
    bool pie = false;                   // MH_PIE (0x00200000)

    u64 entryPoint = 0;                 // LC_MAIN entryoff (dosya ofseti)
    std::string uuid;                   // LC_UUID (8-4-4-4-12)
    std::string platform;               // LC_BUILD_VERSION platform
    std::string minos;                  // "13.4.0"
    std::string sdk;                    // "14.5.0"
    std::string sourceVersion;          // LC_SOURCE_VERSION (A.B.C.d.e)
    u32 loadCmdCount = 0;               // asil ncmds
    u32 segmentCount = 0;
    u32 symtabCount = 0;                // LC_SYMTAB nsyms
    u32 exportSize = 0;                 // LC_DYLD_INFO export trie boyutu
    u32 exportOff = 0;
    std::vector<std::string> exports;   // export trie'den isimler (cap 128)
    std::vector<MachOSection> sections; // cap 96
    std::vector<std::string> linkedLibs;// LC_LOAD_DYLIB/LC_LOAD_WEAK_DYLIB (cap 48)

    // FAT (universal) konteyner
    bool fat = false;
    std::vector<MachOFatArch> fatArchs;
};

class MachO {
public:
    // sniff: "macho" | "macho-fat" | "" (Java class CAFEBABE ayrimi dahil)
    static std::string Sniff(const u8* d, size_t sz);

    // tek arch parse (header'dan itibaren); d zaten bir Mach-O arch ise true
    static bool Parse(const u8* d, size_t sz, MachOInfo& out);

    // FAT konteyner: en buyuk arch'i Parse eder + arch listesini doldurur
    static bool ParseFat(const u8* d, size_t sz, MachOInfo& out);

    // version pack -> "13.4.0" (x.y.z: b2/b1/b0 baytlari)
    static std::string PackedVersionStr(u32 v);

private:
    // ham 32/64 parse; bigEndian bayragi swap karari verir
    static bool ParseOne(const u8* d, size_t sz, MachOInfo& out, bool big, bool is64, bool verboseErrors);
};

} // namespace dumper
