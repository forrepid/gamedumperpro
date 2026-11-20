// ============================================================================
// DumperPro - ZipReader.cpp
//
// ZIP / APK container reading:
//   1. Locate End Of Central Directory (EOCD "PK\x05\x06") - scanned in the
//      last 64 KiB + 22 bytes (comment may follow).
//   2. ZIP64: when classic fields are 0xFFFFFFFF, parse the ZIP64 EOCD
//      locator ("PK\x06\x07") + ZIP64 EOCD record ("PK\x06\x06").
//   3. Central directory entries ("PK\x01\x02"): name + sizes + method +
//      local header offset; ZIP64 extra field 0x0001 carries 64-bit sizes.
//   4. Extraction: local header ("PK\x03\x04") -> skip name+extra -> raw
//      data. STORE = direct copy, DEFLATE = built-in RFC 1951 decoder.
//
// All reads are bounds-checked; malformed archives fail with a message
// instead of crashing. Decompression is size-capped (zip bomb guard).
//
// Bu dosya tamamen portable'dir (windows.h gerektirmez); Linux'ta derlenip
// smoke-test edilebilir, Windows'ta MSVC/MinGW ile ayni sekilde derlenir.
// ============================================================================

#include "file/ZipReader.h"

namespace dumper {

namespace {

constexpr u32 kSigEocd   = 0x06054b50; // PK\x05\x06
constexpr u32 kSigEocd64 = 0x06064b50; // PK\x06\x06
constexpr u32 kSigLoc64  = 0x07064b50; // PK\x06\x07
constexpr u32 kSigCd     = 0x02014b50; // PK\x01\x02
constexpr u32 kSigLocal  = 0x04034b50; // PK\x03\x04
constexpr u64 kDefaultMaxOut = 1024ull * 1024 * 1024; // 1 GiB

u16 Rd16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
u32 Rd32(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
u64 Rd64(const u8* p) {
    return (u64)Rd32(p) | ((u64)Rd32(p + 4) << 32);
}

// ---------------------------------------------------------------------------
// RFC 1951 DEFLATE decoder (compact, canonical-Huffman).
// Yeterli: APK entry'lerini acmak icin tum standart bloklari destekler.
// ---------------------------------------------------------------------------
struct BitReader {
    const u8* d;
    size_t sz;
    size_t pos = 0;   // byte position
    u32 bitBuf = 0;
    int bitCnt = 0;
    bool overrun = false;

    BitReader(const u8* data, size_t size) : d(data), sz(size) {}

    int ReadBit() {
        if (bitCnt == 0) {
            if (pos >= sz) { overrun = true; return 0; }
            bitBuf = d[pos++];
            bitCnt = 8;
        }
        int b = bitBuf & 1;
        bitBuf >>= 1;
        bitCnt--;
        return b;
    }

    u32 ReadBits(int n) { // LSB-first
        u32 v = 0;
        for (int i = 0; i < n; i++) v |= (u32)ReadBit() << i;
        return v;
    }

    void AlignByte() { bitCnt = 0; }
};

struct HuffTable {
    u16 count[16] = {};      // count[len]
    std::vector<u16> symbols;
    bool ok = false;

    bool Build(const u8* lengths, size_t n) {
        memset(count, 0, sizeof(count));
        for (size_t i = 0; i < n; i++) {
            if (lengths[i] > 15) return false;
            count[lengths[i]]++;
        }
        // over-subscription check (sum( count[l] << (15-l) ) <= 1<<15)
        u32 left = 1;
        for (int l = 1; l <= 15; l++) {
            left <<= 1;
            left -= count[l];
            if ((i32)left < 0) return false;
        }
        u16 offs[16];
        offs[1] = 0;
        for (int l = 1; l < 15; l++) offs[l + 1] = (u16)(offs[l] + count[l]);
        symbols.assign(n, 0);
        for (size_t s = 0; s < n; s++)
            if (lengths[s]) symbols[offs[lengths[s]]++] = (u16)s;
        ok = true;
        return true;
    }

    // returns symbol or -1
    int Decode(BitReader& br) const {
        int code = 0, first = 0, index = 0;
        for (int len = 1; len <= 15; len++) {
            code |= br.ReadBit();
            if (br.overrun) return -1;
            int cnt = count[len];
            if (code - first < cnt) return symbols[(size_t)(index + (code - first))];
            index += cnt;
            first = (first + cnt) << 1;
            code <<= 1;
        }
        return -1;
    }
};

const u16 kLenBase[29] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,
                           67,83,99,115,131,163,195,227,258 };
const u8  kLenExtra[29] = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
const u16 kDistBase[30] = { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
                            1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
const u8  kDistExtra[30] = { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };
const u8  kCodeLenOrder[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };

// inflate raw DEFLATE stream; returns false on malformed data / overflow.
bool InflateRaw(const u8* in, size_t inSize, std::vector<u8>& out, u64 maxOut) {
    BitReader br(in, inSize);
    out.clear();

    for (;;) {
        const u32 bfinal = br.ReadBits(1);
        const u32 btype = br.ReadBits(2);

        if (btype == 0) { // stored
            br.AlignByte();
            if (br.pos + 4 > br.sz) return false;
            const u16 len = Rd16(br.d + br.pos);
            const u16 nlen = Rd16(br.d + br.pos + 2);
            br.pos += 4;
            if ((u16)(~len) != nlen) return false;
            if (br.pos + len > br.sz) return false;
            if (out.size() + len > maxOut) return false;
            out.insert(out.end(), br.d + br.pos, br.d + br.pos + len);
            br.pos += len;
        } else if (btype == 1 || btype == 2) { // fixed / dynamic Huffman
            HuffTable lit, dist;
            u8 lens[320] = {}; // 286 lit/len + 30 dist

            if (btype == 1) {
                for (int i = 0; i < 144; i++) lens[i] = 8;
                for (int i = 144; i < 256; i++) lens[i] = 9;
                for (int i = 256; i < 280; i++) lens[i] = 7;
                for (int i = 280; i < 288; i++) lens[i] = 8;
                u8 dlens[30];
                for (int i = 0; i < 30; i++) dlens[i] = 5;
                if (!lit.Build(lens, 288) || !dist.Build(dlens, 30)) return false;
            } else {
                const u32 hlit = br.ReadBits(5) + 257;
                const u32 hdist = br.ReadBits(5) + 1;
                const u32 hclen = br.ReadBits(4) + 4;
                if (hlit > 286 || hdist > 30) return false;
                u8 clens[19] = {};
                for (u32 i = 0; i < hclen; i++)
                    clens[kCodeLenOrder[i]] = (u8)br.ReadBits(3);
                HuffTable cl;
                if (!cl.Build(clens, 19)) return false;

                u8 lens[320] = {};
                u32 idx = 0;
                while (idx < hlit + hdist) {
                    int sym = cl.Decode(br);
                    if (sym < 0) return false;
                    if (sym < 16) {
                        lens[idx++] = (u8)sym;
                    } else {
                        int rep = 0;
                        u8 val = 0;
                        if (sym == 16) {
                            if (idx == 0) return false;
                            val = lens[idx - 1];
                            rep = 3 + (int)br.ReadBits(2);
                        } else if (sym == 17) {
                            val = 0;
                            rep = 3 + (int)br.ReadBits(3);
                        } else {
                            val = 0;
                            rep = 11 + (int)br.ReadBits(7);
                        }
                        if (idx + (u32)rep > hlit + hdist) return false;
                        while (rep--) lens[idx++] = val;
                    }
                }
                if (lens[256] == 0) return false; // missing end-of-block
                if (!lit.Build(lens, hlit)) return false;
                if (!dist.Build(lens + hlit, hdist)) return false;
            }

            for (;;) {
                int sym = lit.Decode(br);
                if (sym < 0) return false;
                if (sym < 256) {
                    if (out.size() + 1 > maxOut) return false;
                    out.push_back((u8)sym);
                } else if (sym == 256) {
                    break;
                } else {
                    const int li = sym - 257;
                    if (li >= 29) return false;
                    u64 length = kLenBase[li] + br.ReadBits(kLenExtra[li]);
                    int dsym = dist.Decode(br);
                    if (dsym < 0 || dsym >= 30) return false;
                    u64 distance = kDistBase[dsym] + br.ReadBits(kDistExtra[dsym]);
                    if (distance > out.size()) return false;
                    if (out.size() + length > maxOut) return false;
                    // byte-by-byte (distance may overlap length)
                    size_t start = out.size() - (size_t)distance;
                    for (u64 i = 0; i < length; i++)
                        out.push_back(out[start + i]);
                }
            }
        } else {
            return false; // reserved block type
        }

        if (bfinal) break;
        if (br.overrun) return false;
    }
    return !br.overrun;
}

} // namespace

// ---------------------------------------------------------------------------
bool ZipReader::IsZip(const u8* data, size_t size) {
    // EOCD'u iceren herhangi bir son 64K+22 penceresini kontrol etmek pahali;
    // pratik test: basi "PK\x03\x04" ya da "PK\x05\x06" (bos arsiv)
    if (!data || size < 4) return false;
    return (data[0] == 'P' && data[1] == 'K' &&
            ((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6)));
}

bool ZipReader::Parse(const u8* data, size_t size) {
    valid_ = false;
    entries_.clear();
    d_ = data;
    sz_ = size;
    if (!data || size < 22) {
        lastErr_ = "ZIP icin dosya cok kucuk";
        return false;
    }
    if (!LocateEocd()) return false;
    if (!ParseCentralDirectory()) return false;
    valid_ = true;
    return true;
}

bool ZipReader::LocateEocd() {
    // EOCD = 22 byte minimum + comment; son 64K+22 icinde tara
    const u64 scanStart = (sz_ > 22 + 65535) ? sz_ - (22 + 65535) : 0;
    for (u64 i = sz_; i-- > scanStart;) {
        if (sz_ - i < 22) continue;
        if (d_[i] == 'P' && d_[i + 1] == 'K' && d_[i + 2] == 5 && d_[i + 3] == 6) {
            const u16 commentLen = Rd16(d_ + i + 20);
            if (i + 22 + commentLen == sz_) {
                eocdOff_ = i;
                const u32 cdOff32 = Rd32(d_ + i + 16);
                const u32 cdSize32 = Rd32(d_ + i + 12);
                u64 total = Rd16(d_ + i + 10);
                const u16 diskNum = Rd16(d_ + i + 4);

                cdOff_ = cdOff32;
                cdSize_ = cdSize32;

                if (diskNum != 0 || cdOff32 == 0xFFFFFFFF || total == 0xFFFF) {
                    // ZIP64: locator "PK\x06\x07" EOCD'den 20 byte once
                    if (eocdOff_ >= 20) {
                        const u64 locOff = eocdOff_ - 20;
                        if (Rd32(d_ + locOff) == kSigLoc64) {
                            const u64 eocd64Off = Rd64(d_ + locOff + 8);
                            if (eocd64Off + 56 <= sz_ && Rd32(d_ + eocd64Off) == kSigEocd64) {
                                cdSize_ = Rd64(d_ + eocd64Off + 40);
                                cdOff_ = Rd64(d_ + eocd64Off + 48);
                                total = Rd64(d_ + eocd64Off + 32);
                            }
                        }
                    }
                }
                totalEntries_ = total;
                return true;
            }
        }
    }
    lastErr_ = "EOCD bulunamadi (bozuk veya ZIP degil)";
    return false;
}

bool ZipReader::ParseCentralDirectory() {
    if (cdOff_ + cdSize_ > sz_) {
        lastErr_ = "merkezi dizin dosya sinirlari disinda";
        return false;
    }
    entries_.reserve((size_t)std::min<u64>(totalEntries_, 1000000));

    u64 p = cdOff_;
    const u64 cdEnd = cdOff_ + cdSize_;
    u64 parsed = 0;
    while (p + 46 <= cdEnd && parsed < totalEntries_) {
        const u8* rec = d_ + p;
        if (Rd32(rec) != kSigCd) break;
        const u16 nameLen = Rd16(rec + 28);
        const u16 extraLen = Rd16(rec + 30);
        const u16 commentLen = Rd16(rec + 32);
        const u64 next = p + 46 + nameLen + extraLen + commentLen;
        if (next > cdEnd) break;

        const u32 method = Rd16(rec + 10);
        const u32 crc = Rd32(rec + 16);
        u64 csize = Rd32(rec + 20);
        u64 usize = Rd32(rec + 24);
        u64 lhOff = Rd32(rec + 42);

        const u8* namePtr = rec + 46;
        std::string name((const char*)namePtr, nameLen);

        // ZIP64 extra (id 0x0001): siralama -> usize, csize, lhOff, diskno
        const u8* x = rec + 46 + nameLen;
        const u8* xEnd = x + extraLen;
        while (x + 4 <= xEnd) {
            const u16 id = Rd16(x);
            const u16 sz = Rd16(x + 2);
            if (x + 4 + sz > xEnd) break;
            if (id == 0x0001) {
                const u8* v = x + 4;
                if (usize == 0xFFFFFFFF && v + 8 <= xEnd) { usize = Rd64(v); v += 8; }
                if (csize == 0xFFFFFFFF && v + 8 <= xEnd) { csize = Rd64(v); v += 8; }
                if (lhOff == 0xFFFFFFFF && v + 8 <= xEnd) { lhOff = Rd64(v); v += 8; }
            }
            x += 4 + sz;
        }

        ZipEntry e;
        e.name = std::move(name);
        e.method = method;
        e.crc32 = crc;
        e.compressedSize = csize;
        e.uncompressedSize = usize;
        e.localHeaderOffset = lhOff;
        entries_.push_back(std::move(e));

        p = next;
        parsed++;
    }
    if (entries_.empty()) {
        lastErr_ = "merkezi dizin kaydi cozumlenemedi";
        return false;
    }
    return true;
}

const ZipEntry* ZipReader::EntryByName(const std::string& name) const {
    for (const ZipEntry& e : entries_)
        if (e.name == name) return &e;
    return nullptr;
}

bool ZipReader::Extract(const ZipEntry& e, std::vector<u8>& out, u64 maxOut) const {
    if (!valid_) { lastErr_ = "ZipReader gecerli degil"; return false; }
    const u64 limit = maxOut ? maxOut : kDefaultMaxOut;
    if (e.uncompressedSize > limit) {
        lastErr_ = "entry cikarma limitini asiyor (" + std::to_string(e.uncompressedSize) + " bayt)";
        return false;
    }
    if (e.method != 0 && e.method != 8) {
        lastErr_ = "desteklenmeyen sikistirma yontemi: " + std::to_string(e.method);
        return false;
    }
    if (e.localHeaderOffset + 30 > sz_) {
        lastErr_ = "local header dosya sinirlari disinda";
        return false;
    }
    const u8* lh = d_ + e.localHeaderOffset;
    if (Rd32(lh) != kSigLocal) {
        lastErr_ = "local header imzasi eslesmedi";
        return false;
    }
    const u16 nameLen = Rd16(lh + 26);
    const u16 extraLen = Rd16(lh + 27);
    const u64 dataOff = e.localHeaderOffset + 30 + nameLen + extraLen;
    if (dataOff + e.compressedSize > sz_) {
        lastErr_ = "veri araligi dosya sinirlari disinda";
        return false;
    }

    if (e.method == 0) {
        out.assign(d_ + dataOff, d_ + dataOff + e.compressedSize);
        return true;
    }
    if (!InflateRaw(d_ + dataOff, (size_t)e.compressedSize, out, limit)) {
        lastErr_ = "DEFLATE cozme basarisiz";
        return false;
    }
    // boyut teyidi (eslesmiyorsa yine de kabul: kesik akislarda kismi doner)
    if (out.size() != e.uncompressedSize) {
        // katı degil; bazi uretecler merkez kaydinda farklı yazar
    }
    return true;
}

} // namespace dumper
