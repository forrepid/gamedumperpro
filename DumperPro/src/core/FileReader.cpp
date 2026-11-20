// ============================================================================
// DumperPro - FileReader.cpp
//
// Offline PE analysis mode: the whole image file is read into memory and
// parsed with PEFile (raw file image, isMapped=false).
//
// Read() translates VA -> RVA -> file offset with full bounds checking:
//   - PE headers map linearly (rva < SizeOfHeaders)
//   - section raw ranges map linearly, truncated raw tails are zero-filled
//   - unmapped zones (bss tails, section gaps, header gaps) are zero-filled
//   - bytes beyond SizeOfImage are zero-filled, never stale memory
//
// Deliberately portable: no Win32 headers in this translation unit.
// ============================================================================

#include "core/MemoryReader.h"
#include "core/PEFile.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

namespace dumper {

namespace {

constexpr u64 kMaxImageFile = 0x80000000ull; // refuse to buffer more than 2 GiB

// copy `run` bytes from file offset `off`; zero-fill whatever the file cannot
// provide (truncated raw section tails)
inline void CopyFromFile(u8* dst, size_t off, size_t run, const std::vector<u8>& file) {
    if (off >= file.size()) {
        memset(dst, 0, run);
        return;
    }
    const size_t can = std::min(run, file.size() - off);
    memcpy(dst, file.data() + off, can);
    if (can < run) memset(dst + can, 0, run - can);
}

} // namespace

// ---------------------------------------------------------------------------
// FileReader
// ---------------------------------------------------------------------------
class FileReader final : public IMemoryReader {
public:
    explicit FileReader(const fs::path& file) { Load(file); }

    bool Read(u64 va, void* out, size_t size) override {
        if (!ok_ || !pe_) {
            if (lastErr_.empty()) lastErr_ = "file reader not initialized";
            return false;
        }
        if (size == 0) return true;
        if (!out) {
            lastErr_ = "null output buffer";
            return false;
        }
        if (va > UINT64_MAX - (u64)size) {
            lastErr_ = "read at " + Hex(va) + " overflows the address range";
            return false;
        }
        if (va < base_) {
            lastErr_ = "read at " + Hex(va) + " is below the image base " + Hex(base_);
            return false;
        }

        const u64 imgEnd = base_ + (u64)pe_->SizeOfImage();
        if (va >= imgEnd) {
            lastErr_ = "read at " + Hex(va) + " is outside the image (" + Hex(base_) + " - " + Hex(imgEnd) + ")";
            return false;
        }

        const size_t avail = (size_t)std::min<u64>((u64)size, imgEnd - va);
        u8* dst = (u8*)out;

        // bytes beyond the mapped image are defined as zero, never stale memory
        if (avail < size) memset(dst + avail, 0, size - avail);

        const u32 rva0 = (u32)(va - base_);
        const std::vector<PESection>& secs = pe_->Sections();
        const u32 sizeHeaders = pe_->SizeOfHeaders();
        size_t done = 0;

        while (done < avail) {
            const size_t prev = done;
            const u32 r = rva0 + (u32)done; // done < avail <= SizeOfImage - rva0, so r fits u32
            const u32 off = pe_->RvaToOffset(r); // authoritative mapped-ness (0xFFFFFFFF = unmapped)

            if (off != 0xFFFFFFFFu) {
                // mapped: the linear mapping extends over the owning region
                size_t run = avail - done;
                if (r < sizeHeaders) {
                    run = std::min(run, (size_t)(sizeHeaders - r));
                } else {
                    // first matching section, same order as PEFile::RvaToOffset
                    const PESection* sec = nullptr;
                    for (const PESection& s : secs) {
                        if (r >= s.va && r < s.va + std::max(s.vs, s.rawSize)) { sec = &s; break; }
                    }
                    if (sec) {
                        const u32 delta = r - sec->va;
                        if (delta < sec->rawSize)
                            run = std::min(run, (size_t)(sec->rawSize - delta));
                        else
                            run = 1; // inconsistent state; re-evaluate the next byte
                    } else {
                        run = 1; // should not happen for a valid PE; re-evaluate per byte
                    }
                }
                CopyFromFile(dst + done, (size_t)off, run, data_);
                done += run;
            } else {
                // unmapped (bss tail, section gap, header gap): zero-fill until
                // the next mapped rva (end of this virtual zone / next section start)
                u64 next = ~0ull;
                for (const PESection& s : secs) {
                    const u64 secEnd = (u64)s.va + std::max(s.vs, s.rawSize);
                    if (r >= s.va && r < secEnd)
                        next = std::min<u64>(next, secEnd);
                    else if (s.va > r)
                        next = std::min<u64>(next, s.va);
                }
                const size_t run = (next == ~0ull) ? (avail - done)
                                                   : std::min<size_t>(avail - done, (size_t)(next - r));
                memset(dst + done, 0, run);
                done += run;
            }

            if (done == prev) { // defensive: never stall on malformed input
                memset(dst + done, 0, avail - done);
                break;
            }
        }
        return true;
    }

    std::vector<ModuleInfo> Modules() override {
        std::vector<ModuleInfo> out;
        if (!ok_ || !pe_) return out;
        ModuleInfo m;
        m.name = name_;
        m.base = base_;
        m.size = pe_->SizeOfImage();
        out.push_back(std::move(m));
        return out;
    }

    u64 MainModuleBase() override { return base_; }
    std::string TargetName() override { return name_; }
    bool IsLiveProcess() const override { return false; }
    bool IsOK() const override { return ok_; }
    std::string LastError() const override { return lastErr_; }

private:
    void Load(const fs::path& file) {
        pe_.reset();
        data_.clear();
        base_ = 0;
        ok_ = false;

        name_ = file.filename().string();
        if (name_.empty()) name_ = file.string();

        std::error_code ec;
        if (!fs::exists(file, ec) || ec) {
            lastErr_ = "file not found: " + file.string();
            return;
        }
        if (!fs::is_regular_file(file, ec) || ec) {
            lastErr_ = "not a regular file: " + file.string();
            return;
        }
        const u64 fsize = fs::file_size(file, ec);
        if (ec) {
            lastErr_ = "cannot stat '" + file.string() + "': " + ec.message();
            return;
        }
        if (fsize == 0) {
            lastErr_ = "file is empty: " + file.string();
            return;
        }
        if (fsize > kMaxImageFile) {
            lastErr_ = "file too large to buffer (" + str::HumanSize(fsize) + "): " + file.string();
            return;
        }

        std::ifstream in(file, std::ios::binary);
        if (!in.good()) {
            lastErr_ = "cannot open '" + file.string() + "' for reading";
            return;
        }
        data_.resize((size_t)fsize);
        in.read(reinterpret_cast<char*>(data_.data()), (std::streamsize)fsize);
        if ((u64)in.gcount() != fsize) {
            lastErr_ = "short read on '" + file.string() + "'";
            data_.clear();
            return;
        }

        if (!PEFile::IsPE(data_.data(), data_.size())) {
            lastErr_ = "not a x64 PE image (.exe/.dll). APK/ELF/DEX inputs are routed to the static analyzer (file mode / --serve)";
            Log::Err("%s", lastErr_.c_str());
            return;
        }

        pe_ = std::make_unique<PEFile>();
        if (!pe_->Parse(data_.data(), data_.size(), false) || !pe_->Valid()) {
            lastErr_ = "unsupported or malformed PE image (x64 PE32+ required): " + file.string();
            Log::Err("%s", lastErr_.c_str());
            return;
        }

        base_ = pe_->ImageBase();
        ok_ = true;
        Log::Ok("parsed %s: image base %s, size %s, %zu sections",
                name_.c_str(), Hex(base_).c_str(), str::HumanSize((u64)pe_->SizeOfImage()).c_str(),
                pe_->Sections().size());
    }

    std::vector<u8> data_;          // raw file image (pe_ views into it)
    std::unique_ptr<PEFile> pe_;
    u64 base_ = 0;
    bool ok_ = false;
    std::string name_;
    std::string lastErr_;
};

// ---------------------------------------------------------------------------
// CreateFileReader - factory declared in MemoryReader.h.
// Returns a live (possibly IsOK()==false) reader so LastError() stays
// reportable; callers must check IsOK().
// ---------------------------------------------------------------------------
std::unique_ptr<IMemoryReader> CreateFileReader(const fs::path& file) {
    return std::make_unique<FileReader>(file);
}

} // namespace dumper
