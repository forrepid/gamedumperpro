// DumperPro - IMemoryReader shared helpers + ModuleImage loading
#include "core/MemoryReader.h"
#include "core/PEFile.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"
#include "utils/Progress.h"

namespace dumper {

// ---------------------------------------------------------------------------
// string readers
// ---------------------------------------------------------------------------

std::string IMemoryReader::ReadCString(u64 va, size_t max) {
    std::string out;
    out.reserve(64);
    char buf[256];
    while (out.size() < max) {
        const size_t chunk = std::min(sizeof(buf), max - out.size());
        if (!Read(va + out.size(), buf, chunk)) break;
        bool done = false;
        for (size_t i = 0; i < chunk; i++) {
            if (buf[i] == 0) { done = true; break; }
            out.push_back(buf[i]);
        }
        if (done) break;
    }
    return out;
}

std::string IMemoryReader::ReadWideString(u64 va, size_t maxChars) {
    std::vector<u16> out;
    out.reserve(64);
    u16 buf[128];
    while (out.size() < maxChars) {
        const size_t chunk = std::min<size_t>(128, maxChars - out.size());
        if (!Read(va + out.size() * 2ull, buf, chunk * 2)) break;
        bool done = false;
        for (size_t i = 0; i < chunk; i++) {
            if (buf[i] == 0) { done = true; break; }
            out.push_back(buf[i]);
        }
        if (done) break;
    }
    return str::WideToUtf8(out.data(), out.size());
}

// ---------------------------------------------------------------------------
// ModuleImage
// ---------------------------------------------------------------------------

bool ModuleImage::LoadFromFile(const fs::path& file) {
    Name = file.filename().string();

    std::error_code ec;
    const u64 fsize = fs::file_size(file, ec);
    if (ec || fsize == 0 || fsize > 4ull * 1024 * 1024 * 1024) {
        Log::Err("cannot stat/read file: %s", file.string().c_str());
        return false;
    }

    std::vector<u8> raw((size_t)fsize);
    {
        std::ifstream f(file, std::ios::binary);
        if (!f.good()) {
            Log::Err("cannot open file: %s", file.string().c_str());
            return false;
        }
        f.read((char*)raw.data(), (std::streamsize)raw.size());
        if ((size_t)f.gcount() != raw.size()) {
            Log::Err("short read on file: %s", file.string().c_str());
            return false;
        }
    }

    pe = std::make_unique<PEFile>();
    if (!pe->Parse(raw.data(), raw.size(), false)) {
        Log::Err("not a x64 PE image: %s", file.string().c_str());
        pe.reset();
        return false;
    }

    // expand raw file -> memory image layout (offset == RVA)
    Data.assign(pe->SizeOfImage(), 0);
    const u32 hdrBytes = std::min<u32>(pe->SizeOfHeaders(), (u32)raw.size());
    memcpy(Data.data(), raw.data(), hdrBytes);
    for (const PESection& s : pe->Sections()) {
        const u32 copy = std::min<u32>(s.rawSize, (u32)raw.size() - std::min<u32>(s.rawOff, (u32)raw.size()));
        if (copy == 0) continue;
        if (s.va + copy > Data.size()) continue;
        memcpy(Data.data() + s.va, raw.data() + s.rawOff, copy);
    }

    Base = pe->ImageBase();
    Log::Debug("ModuleImage(file): %s imageBase=%s size=%s sections=%u",
               Name.c_str(), Hex(Base).c_str(), str::HumanSize(Data.size()).c_str(), (u32)pe->Sections().size());
    return true;
}

bool ModuleImage::UnmapToRawFile(std::vector<u8>& raw) const {
    raw.clear();
    if (!pe || !pe->Valid() || Data.empty()) return false;

    // raw dosya boyutu: en buyuk rawOff+rawSize (basliklar dahil)
    u32 end = pe->SizeOfHeaders();
    for (const PESection& s : pe->Sections())
        end = std::max<u32>(end, s.rawOff + s.rawSize);
    if (end == 0 || end > (u32)Data.size() * 2 + (1u << 20)) return false; // imkansiz tablo

    raw.assign(end, 0);

    // basliklar: mapped imajin ilk SizeOfHeaders bayti aynen yerlesir
    const u32 hdrBytes = std::min<u32>(pe->SizeOfHeaders(), (u32)Data.size());
    memcpy(raw.data(), Data.data(), hdrBytes);

    // section'lar: mapped[va .. va+copy] -> raw[rawOff .. rawOff+copy]
    for (const PESection& s : pe->Sections()) {
        const u32 copy = std::min<u32>(s.rawSize, s.vs ? s.vs : s.rawSize);
        if (copy == 0) continue;
        if (s.va + copy > Data.size() || s.rawOff + copy > raw.size()) continue;
        memcpy(raw.data() + s.rawOff, Data.data() + s.va, copy);
    }
    return true;
}

bool ModuleImage::LoadFromReader(IMemoryReader& r, const ModuleInfo& m) {
    if (!m.base || !m.size) {
        Log::Err("invalid module info (base/size zero)");
        return false;
    }
    Name = m.name;
    Data.assign(m.size, 0);

    // chunked snapshot with progress (modules can be hundreds of MB)
    constexpr size_t kChunk = 1ull << 20; // 1 MB
    Progress p("Module", (m.size + kChunk - 1) / kChunk);
    for (u64 done = 0; done < m.size; done += kChunk) {
        const u64 take = std::min<u64>(kChunk, m.size - done);
        if (!r.Read(m.base + done, Data.data() + done, (size_t)take)) {
            Log::Warn("module read hole at +%s (zero-filled)", Hex(done).c_str());
            // keep zero fill for the missing chunk, continue
        }
        p.Add();
        if (take < kChunk) break;
    }
    p.Done();

    pe = std::make_unique<PEFile>();
    const bool mappedOk = pe->Parse(Data.data(), Data.size(), true);
    if (!mappedOk) {
        Log::Err("module image is not a x64 PE (packed or protected?): %s", Name.c_str());
        pe.reset();
        return false;
    }
    Base = m.base;
    Log::Debug("ModuleImage(process): %s base=%s size=%s",
               Name.c_str(), Hex(Base).c_str(), str::HumanSize(Data.size()).c_str());
    return true;
}

bool ModuleImage::InExecSection(u64 va) const {
    if (!pe || !pe->Valid() || !Contains(va)) return false;
    const PESection* s = pe->SectionAtRva(VaToRva(va));
    return s && s->exec;
}

bool ModuleImage::InDataSection(u64 va) const {
    if (!pe || !pe->Valid() || !Contains(va)) return false;
    const PESection* s = pe->SectionAtRva(VaToRva(va));
    return s && !s->exec && s->read;
}

} // namespace dumper
