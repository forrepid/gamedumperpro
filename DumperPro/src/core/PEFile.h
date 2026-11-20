// DumperPro - portable PE parsing (no windows.h needed)
#pragma once
#include "../framework.h"

namespace dumper {

struct PESection {
    std::string name;
    u32 va = 0, vs = 0;         // virtual address / virtual size
    u32 rawOff = 0, rawSize = 0;
    u32 chars = 0;
    bool exec = false, read = false, write = false;
};

struct ExportEntry {
    std::string name;
    u32 rva = 0;
    u32 ord = 0;
};

// --- yeni veri tipleri (arama/cikarma genislemesi) -------------------------
// debug directory kaydi (IMAGE_DEBUG_DIRECTORY)
struct PEDebugEntry {
    u32 type = 0;            // 1=COFF 2=CodeView 3=FPO 4=MISC 6=REPRO 16=POGO 17=ILTCG
    std::string typeName;    // insan-okur etiket
    u32 sizeOfData = 0;
    u32 rva = 0;             // AddressOfRawData (0 olabilir; diskte PointerToRawData)
    u32 fileOff = 0;         // PointerToRawData
    // CodeView (RSDS/NB10/NB11) dolu alanlar:
    std::string cvFormat;    // "RSDS" | "NB10" | "NB11" | ""
    std::string pdbPath;     // symbol dosya yolu
    std::string guid;        // RSDS: 32 hex karakter (8+2+2+8 bayt sirali)
    u32 age = 0;             // PDB age
    u32 timestamp = 0;       // NB10/NB11/MISC stamp
    std::string miscName;    // MISC tipi .dbg adi
};

// import kaydi (IMAGE_IMPORT_DESCRIPTOR + thunk cozumlu)
struct PEImportDll {
    std::string dllName;
    std::vector<std::string> funcs;   // import edilen fonksiyon adlari (cap'li)
    u32 funcCount = 0;                // gercek thunk sayisi (cap uzerine de sayilir)
    bool delayedViaName = false;      // isim rezolvasyonlu (bound import yok)
};

// VS_VERSIONINFO'dan cekilen kaynak (resource) degerleri
struct PEVersionInfo {
    bool present = false;
    u32 rva = 0;
    u32 size = 0;
    u16 fileMajor = 0, fileMinor = 0, fileBuild = 0, fileRev = 0;
    u16 prodMajor = 0, prodMinor = 0, prodBuild = 0, prodRev = 0;
    u32 flags = 0;                    // dwFileFlags (DEBUG|PRERELEASE|PATCHED...)
    std::string companyName, productName, fileDescription, fileVersion;
    std::string productVersion, internalName, originalFilename, legalCopyright;
    std::string comments;
};

// MSVC Rich Header (toolchain parmak izi)
struct PERichEntry {
    u16 prodId = 0;
    u16 build = 0;
    u32 count = 0;
    std::string toolName;   // bilinen prodId eslesmesi; bilinmeyen "Tool 0xNNNN"
};

struct PERichHeader {
    bool present = false;
    u32 offset = 0;         // dosya ofseti (DanS)
    u32 key = 0;            // XOR anahtari
    u32 checksum = 0;
    std::vector<PERichEntry> tools;
};

// TLS callback
struct PETlsCallback {
    u64 va = 0;
    u32 rva = 0;
    std::string section;    // icinde bulundugu bolum
};

// bolum Shannon entropisi (packer/paketteleme tespiti)
struct PESectionEntropy {
    std::string name;
    double entropy = 0.0;
    u32 rawSize = 0;
    bool high = false;      // >= 7.2
    std::string packerHint; // .vmp0/.themida/UPX0 vs.
};

// MSVC RTTI sınıf adı (CompleteObjectLocator + TypeDescriptor taramasi)
struct PERttiClass {
    std::string name;       // demangled: "Namespace::Class" veya ham ".?AV..."
    std::string mangled;
    u32 colRva = 0;         // CompleteObjectLocator RVA (vtable'in +0 yapisina baglanir)
    u32 typeDescRva = 0;
    u32 classDescRva = 0;
    u32 numBases = 0;       // ClassHierarchyDescriptor
    bool virtualBase = false; // COL sig==1 (imagebase goreli / /vdso)
};

class PEFile {
public:
    // data must stay alive while the PEFile is used.
    // isMapped=false -> raw file image (RVA != file offset)
    // isMapped=true  -> already-mapped image (RVA == buffer offset)
    bool Parse(const u8* data, size_t size, bool isMapped);

    bool Valid() const { return valid_; }

    u64 ImageBase() const { return imgBase_; }
    u32 SizeOfImage() const { return sizeImage_; }
    u32 SizeOfHeaders() const { return sizeHeaders_; }

    // raw file offset of an RVA (for isMapped=false). returns 0xFFFFFFFF when unmappable
    u32 RvaToOffset(u32 rva) const;

    const std::vector<PESection>& Sections() const { return secs_; }
    const PESection* SectionAtRva(u32 rva) const;
    const PESection* SectionByName(const std::string& lowerName) const;

    std::vector<ExportEntry> Exports() const;

    // --- yeni arama/cikarma veri tipleri ---
    std::vector<PEDebugEntry> DebugDirectory() const;          // data dir idx 6
    std::vector<PEImportDll> Imports() const;                 // data dir idx 1
    PEVersionInfo VersionResource() const;                    // data dir idx 2 (VS_VERSIONINFO)
    PERichHeader RichHeader() const;                          // DOS stub toolchain
    std::vector<PETlsCallback> TlsCallbacks() const;          // data dir idx 9
    std::vector<PESectionEntropy> SectionEntropy() const;     // bolum entropileri
    std::vector<PERttiClass> RttiClasses(size_t maxScan = 8192) const; // MSVC RTTI

    // UE version markers found in the image ("Release-4.27", "Release-5.3", ...)
    std::vector<std::string> VersionStrings() const;

    static bool IsPE(const u8* data, size_t size);

private:
    const u8* d_ = nullptr;
    size_t sz_ = 0;
    bool mapped_ = false;
    bool valid_ = false;
    u64 imgBase_ = 0;
    u32 sizeImage_ = 0, sizeHeaders_ = 0;
    u16 machine_ = 0;
    u32 exportDirRva_ = 0, exportDirSize_ = 0;
    u32 dataDirsRva_[16] = {0};
    u32 dataDirsSize_[16] = {0};
    std::vector<PESection> secs_;
};

} // namespace dumper
