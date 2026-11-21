// DumperPro - memory reader abstraction (process / file / kernel) + module image snapshot
#pragma once
#include "../framework.h"
#include "core/PEFile.h"

namespace dumper {

struct ModuleInfo {
    std::string name;
    u64 base = 0;
    u32 size = 0;
};

class IMemoryReader {
public:
    virtual ~IMemoryReader() = default;

    virtual bool Read(u64 va, void* out, size_t size) = 0;
    virtual bool Write(u64 va, const void* data, size_t size) { (void)va; (void)data; (void)size; return false; }
    virtual std::vector<ModuleInfo> Modules() = 0;
    virtual u64 MainModuleBase() = 0;
    virtual std::string TargetName() = 0;
    virtual bool IsLiveProcess() const = 0;
    virtual bool IsOK() const = 0;
    virtual std::string LastError() const = 0;
    // Highest valid address the reader can serve, or 0 = unknown/not applicable.
    // LeechCore reports the device paMax (LC_OPT_CORE_ADDR_MAX); other backends
    // leave the default (0) and callers fall back to their own limits.
    virtual u64 MaxAddress() const { return 0; }

    inline bool ReadU8 (u64 a, u8& v)  { return Read(a, &v, 1); }
    inline bool ReadU16(u64 a, u16& v) { return Read(a, &v, 2); }
    inline bool ReadU32(u64 a, u32& v) { return Read(a, &v, 4); }
    inline bool ReadU64(u64 a, u64& v) { return Read(a, &v, 8); }
    inline bool ReadI32(u64 a, i32& v) { return Read(a, &v, 4); }
    inline bool ReadPtr(u64 a, u64& v) { return Read(a, &v, 8); }
    // tipli okumalar (DataType modulu ile ayni yorum: little-endian, IEEE 754)
    inline bool ReadI8 (u64 a, i8& v)   { return Read(a, &v, 1); }
    inline bool ReadI16(u64 a, i16& v)  { return Read(a, &v, 2); }
    inline bool ReadI64(u64 a, i64& v)  { return Read(a, &v, 8); }
    inline bool ReadF32(u64 a, float& v){ return Read(a, &v, 4); }
    inline bool ReadF64(u64 a, double& v){ return Read(a, &v, 8); }

    inline u64 ReadU64Or(u64 a, u64 def = 0) { u64 v = def; ReadU64(a, v); return v; }
    inline u32 ReadU32Or(u64 a, u32 def = 0) { u32 v = def; ReadU32(a, v); return v; }
    inline i32 ReadI32Or(u64 a, i32 def = 0) { i32 v = def; ReadI32(a, v); return v; }
    inline u64 ReadPtrOr(u64 a, u64 def = 0) { u64 v = def; ReadPtr(a, v); return v; }
    inline float ReadF32Or(u64 a, float def = 0.0f) { float v = def; ReadF32(a, v); return v; }
    inline double ReadF64Or(u64 a, double def = 0.0) { double v = def; ReadF64(a, v); return v; }

    template <class T> inline T ReadVal(u64 va) { T v{}; Read(va, &v, sizeof(T)); return v; }

    std::string ReadCString(u64 va, size_t max = 4096);
    std::string ReadWideString(u64 va, size_t maxChars = 4096);
};

std::unique_ptr<IMemoryReader> CreateProcessReader(const std::string& procName, u32 pid, bool kernelAssisted);
std::unique_ptr<IMemoryReader> CreateFileReader(const fs::path& file);

// ---------------------------------------------------------------------------
// ModuleImage: local copy of a module using UNIFORM addressing.
//   Data is always stored in "memory image layout": Data offset == RVA.
//   - process mode : snapshot of the mapped module (RVA == offset already)
//   - file mode    : raw PE file expanded to memory layout at load time
// ---------------------------------------------------------------------------
class ModuleImage {
public:
    std::string Name;
    u64 Base = 0;               // runtime base (process) or preferred ImageBase (file)
    std::vector<u8> Data;       // memory-image layout
    std::unique_ptr<PEFile> pe; // parsed from raw buffer (file mode) or mapped buffer (process mode)

    bool LoadFromFile(const fs::path& file);
    bool LoadFromReader(IMemoryReader& r, const ModuleInfo& m);

    inline u32 SizeOfImage() const { return pe ? pe->SizeOfImage() : (u32)Data.size(); }
    inline u64 RvaToVa(u32 rva) const { return Base + rva; }
    inline u32 VaToRva(u64 va) const { return (u32)(va - Base); }
    inline const u8* RvaPtr(u32 rva) const { return (rva < Data.size()) ? (Data.data() + rva) : nullptr; }
    inline const u8* VaPtr(u64 va) const {
        if (va < Base) return nullptr;
        return RvaPtr(VaToRva(va));
    }
    inline bool Contains(u64 va) const { return va >= Base && va < Base + SizeOfImage(); }

    bool InExecSection(u64 va) const;
    bool InDataSection(u64 va) const;
};

} // namespace dumper
