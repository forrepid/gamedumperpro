// ============================================================================
// DumperPro - ZipReader.h
//
// Portable ZIP container reader (APK / .zip / .obb): central directory
// parsing + entry extraction. Supports STORE (method 0) and DEFLATE
// (method 8, RFC 1951 decoder built in - no external dependency).
// ZIP64 extended records are handled for >4 GiB archives.
//
// Formats verified against APPNOTE.TXT (PKWARE .ZIP File Format
// Specification) and the AOSP APK packaging layout.
// ============================================================================
#pragma once
#include "../framework.h"

namespace dumper {

struct ZipEntry {
    std::string name;
    u64 compressedSize = 0;
    u64 uncompressedSize = 0;
    u32 method = 0;          // 0 = STORE, 8 = DEFLATE
    u64 localHeaderOffset = 0;
    u32 crc32 = 0;
};

class ZipReader {
public:
    // data must stay alive while ZipReader is used
    bool Parse(const u8* data, size_t size);

    bool Valid() const { return valid_; }
    const std::vector<ZipEntry>& Entries() const { return entries_; }
    const ZipEntry* EntryByName(const std::string& name) const;
    std::string LastError() const { return lastErr_; }

    // extract an entry; on success fills out with uncompressedSize bytes.
    // maxOut limits decompressed size (bomb protection); 0 = 1 GiB default.
    bool Extract(const ZipEntry& e, std::vector<u8>& out, u64 maxOut = 0) const;

    static bool IsZip(const u8* data, size_t size);

private:
    bool LocateEocd();
    bool ParseCentralDirectory();

    const u8* d_ = nullptr;
    size_t sz_ = 0;
    bool valid_ = false;
    u64 eocdOff_ = 0;
    u64 cdOff_ = 0, cdSize_ = 0;
    u64 totalEntries_ = 0;
    std::vector<ZipEntry> entries_;
    mutable std::string lastErr_; // const Extract() icin mutable
};

} // namespace dumper
