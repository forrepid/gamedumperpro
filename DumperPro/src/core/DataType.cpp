// ============================================================================
// DumperPro - DataType.cpp
//
// Merkezi veri tipi kayit sisteminin uygulaması. Tum bayt yorumlamalari
// little-endian'dir (x86/x64 Windows hedefi); kayan nokta IEEE 754 beklenir.
// Thread-safe: durum yok, tum metotlar duz fonksiyonlar.
// ============================================================================

#include "core/DataType.h"
#include "utils/StrUtil.h"

#include <cmath>
#include <cstdlib>

namespace dumper {

namespace {

// ---- alias tablosu ---------------------------------------------------------
struct TypeAlias {
    const char* name;
    DType t;
};

const TypeAlias kAliases[] = {
    // 1 bayt
    {"i8", DType::I8},      {"int8", DType::I8},    {"sbyte", DType::I8},
    {"u8", DType::U8},      {"uint8", DType::U8},   {"byte", DType::U8},
    // 2 bayt
    {"i16", DType::I16},    {"int16", DType::I16},  {"short", DType::I16},
    {"u16", DType::U16},    {"uint16", DType::U16}, {"ushort", DType::U16}, {"word", DType::U16},
    // 4 bayt
    {"i32", DType::I32},    {"int32", DType::I32},  {"int", DType::I32},    {"dword", DType::I32},
    {"u32", DType::U32},    {"uint32", DType::U32}, {"uint", DType::U32},
    // 8 bayt
    {"i64", DType::I64},    {"int64", DType::I64},  {"longlong", DType::I64},
    {"u64", DType::U64},    {"uint64", DType::U64}, {"qword", DType::U64},
    // kayan nokta
    {"f32", DType::F32},    {"float", DType::F32},  {"float32", DType::F32},
    {"f64", DType::F64},    {"double", DType::F64}, {"float64", DType::F64},
    // bool / bit
    {"bool", DType::Bool},  {"boolean", DType::Bool},
    {"bit", DType::Bit},
    // metin
    {"str", DType::StrA},   {"string", DType::StrA}, {"ascii", DType::StrA},
    {"str16", DType::StrW}, {"utf16", DType::StrW},  {"wide", DType::StrW}, {"wstring", DType::StrW},
    // pointer
    {"ptr", DType::Ptr},    {"pointer", DType::Ptr},
    // vektorler
    {"vec2", DType::Vec2},      {"vector2", DType::Vec2}, {"vector2d", DType::Vec2}, {"fvector2d", DType::Vec2},
    {"vec3", DType::Vec3},      {"vector3", DType::Vec3}, {"vector3d", DType::Vec3}, {"fvector", DType::Vec3},
    {"frotator", DType::Vec3},  // FRotator = 3 float (pitch, yaw, roll)
    {"vec4", DType::Vec4},      {"vector4", DType::Vec4}, {"vector4d", DType::Vec4}, {"fvector4", DType::Vec4},
};

// ---- LE okuyucu ------------------------------------------------------------
u64 RdLE(const u8* p, size_t n) {
    u64 v = 0;
    for (size_t k = 0; k < n; k++) v |= (u64)p[k] << (8 * k);
    return v;
}

void WrLE(std::vector<u8>& out, u64 v, size_t n) {
    for (size_t k = 0; k < n; k++) out.push_back((u8)((v >> (8 * k)) & 0xFF));
}

// ---- float bicimlendirme ----------------------------------------------------
// %g tabanli, gereksiz sifirlari kirpan gorunum (3.1400001 yerine 3.14)
std::string TrimNum(const char* s) {
    std::string out(s);
    // bilimsel gosterim on eki yoksa sondaki sifirlari kirp ("1.500" -> "1.5")
    if (out.find('e') == std::string::npos && out.find('E') == std::string::npos) {
        const size_t dot = out.find('.');
        if (dot != std::string::npos) {
            size_t last = out.size() - 1;
            while (last > dot && out[last] == '0') last--;
            if (last == dot) last--;    // "1." -> "1"
            out.resize(last + 1);
        }
    }
    return out;
}

std::string FmtFloat(double v, int sigDigits) {
    if (std::isnan(v)) return "NaN";
    if (std::isinf(v)) return v > 0 ? "Inf" : "-Inf";
    char buf[64];
    snprintf(buf, sizeof(buf), "%.*g", sigDigits, v);
    return TrimNum(buf);
}

// ---- imzali tamsayi girdisi -------------------------------------------------
bool ParseSignedI64(const std::string& raw, long long& out, std::string& err) {
    std::string s = str::Trim(raw);
    if (s.empty()) { err = "bos deger"; return false; }
    // negatif sayilar yalnizca desimal; pozitiflerde 0x kabul
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(s.c_str(), &end, 0);   // base 0: 0x otomatik
    if (errno == ERANGE || end == s.c_str() || (end && *end != '\0')) {
        err = "gecersiz tamsayi: " + s;
        return false;
    }
    out = v;
    return true;
}

bool ParseUnsignedU64(const std::string& raw, unsigned long long& out, std::string& err) {
    std::string s = str::Trim(raw);
    if (s.empty()) { err = "bos deger"; return false; }
    // "-" ile baslayan imzali girdiyi reddet (u64 arama icin anlamli degil)
    if (s[0] == '-') { err = "isaretsiz tip negatif kabul etmez: " + s; return false; }
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 0);
    if (errno == ERANGE || end == s.c_str() || (end && *end != '\0')) {
        err = "gecersiz tamsayi: " + s;
        return false;
    }
    out = v;
    return true;
}

// sabit boyutlu tam sayi encode ortak akisi
bool EncodeInt(DType t, const std::string& input, std::vector<u8>& out, std::string& err) {
    switch (t) {
    case DType::I8: {
        long long v;
        if (!ParseSignedI64(input, v, err)) return false;
        if (v < -128 || v > 127) { err = "i8 araligi -128..127"; return false; }
        WrLE(out, (u64)(u8)(i8)v, 1);
        return true;
    }
    case DType::U8: {
        unsigned long long v;
        if (!ParseUnsignedU64(input, v, err)) return false;
        if (v > 0xFF) { err = "u8 araligi 0..255"; return false; }
        WrLE(out, v, 1);
        return true;
    }
    case DType::I16: {
        long long v;
        if (!ParseSignedI64(input, v, err)) return false;
        if (v < -32768 || v > 32767) { err = "i16 araligi -32768..32767"; return false; }
        WrLE(out, (u64)(u16)(i16)v, 2);
        return true;
    }
    case DType::U16: {
        unsigned long long v;
        if (!ParseUnsignedU64(input, v, err)) return false;
        if (v > 0xFFFF) { err = "u16 araligi 0..65535"; return false; }
        WrLE(out, v, 2);
        return true;
    }
    case DType::I32: {
        long long v;
        if (!ParseSignedI64(input, v, err)) return false;
        if (v < -2147483648LL || v > 2147483647LL) { err = "i32 araligi -2147483648..2147483647"; return false; }
        WrLE(out, (u64)(u32)(i32)v, 4);
        return true;
    }
    case DType::U32: {
        unsigned long long v;
        if (!ParseUnsignedU64(input, v, err)) return false;
        if (v > 0xFFFFFFFFull) { err = "u32 araligi 0..4294967295"; return false; }
        WrLE(out, v, 4);
        return true;
    }
    case DType::I64: {
        long long v;
        if (!ParseSignedI64(input, v, err)) return false;
        WrLE(out, (u64)(i64)v, 8);
        return true;
    }
    case DType::U64: {
        unsigned long long v;
        if (!ParseUnsignedU64(input, v, err)) return false;
        WrLE(out, v, 8);
        return true;
    }
    default: return false;
    }
}

} // namespace

// ============================================================================
// tip metadata
// ============================================================================
bool DataType::FromName(const std::string& nameRaw, DType& out) {
    const std::string name = str::Lower(str::Trim(nameRaw));
    if (name.empty()) return false;
    for (const TypeAlias& a : kAliases) {
        if (name == a.name) { out = a.t; return true; }
    }
    return false;
}

const char* DataType::Name(DType t) {
    switch (t) {
    case DType::I8:   return "i8";
    case DType::U8:   return "u8";
    case DType::I16:  return "i16";
    case DType::U16:  return "u16";
    case DType::I32:  return "i32";
    case DType::U32:  return "u32";
    case DType::I64:  return "i64";
    case DType::U64:  return "u64";
    case DType::F32:  return "f32";
    case DType::F64:  return "f64";
    case DType::Bool: return "bool";
    case DType::Bit:  return "bit";
    case DType::StrA: return "str";
    case DType::StrW: return "str16";
    case DType::Ptr:  return "ptr";
    case DType::Vec2: return "vec2";
    case DType::Vec3: return "vec3";
    case DType::Vec4: return "vec4";
    default:          return "?";
    }
}

size_t DataType::SizeOf(DType t) {
    switch (t) {
    case DType::I8:
    case DType::U8:
    case DType::Bool:
    case DType::Bit:  return 1;
    case DType::I16:
    case DType::U16:  return 2;
    case DType::I32:
    case DType::U32:
    case DType::F32:  return 4;
    case DType::I64:
    case DType::U64:
    case DType::F64:
    case DType::Ptr:  return 8;
    case DType::Vec2: return 8;
    case DType::Vec3: return 12;
    case DType::Vec4: return 16;
    case DType::StrA:
    case DType::StrW: return 0;   // degisken (NUL'a kadar)
    default:          return 0;
    }
}

// ============================================================================
// decode: bayt -> deger
// ============================================================================
TypedValue DataType::Decode(const u8* data, size_t avail, DType t,
                            int bitIndex, size_t maxChars) {
    TypedValue tv;
    tv.type = t;
    if (avail == 0) { tv.note = "veri yok"; return tv; }
    if (t == DType::Bit && (bitIndex < 0 || bitIndex > 7)) bitIndex = 0;

    char buf[128];
    const size_t sz = SizeOf(t);

    if (sz != 0 && avail < sz) {
        char nb[64];
        snprintf(nb, sizeof(nb), "eksik bayt (gerekli %zu, var %zu)", sz, avail);
        tv.note = nb;
        return tv;
    }

    switch (t) {
    case DType::I8:
        snprintf(buf, sizeof(buf), "%d", (int)(i8)data[0]);
        tv.value = buf; tv.ok = true; tv.usedBytes = 1;
        return tv;

    case DType::U8:
        snprintf(buf, sizeof(buf), "%u", (unsigned)data[0]);
        tv.value = buf; tv.ok = true; tv.usedBytes = 1;
        return tv;

    case DType::I16: {
        const i16 v = (i16)RdLE(data, 2);
        snprintf(buf, sizeof(buf), "%d", (int)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 2;
        return tv;
    }
    case DType::U16: {
        const u16 v = (u16)RdLE(data, 2);
        snprintf(buf, sizeof(buf), "%u", (unsigned)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 2;
        return tv;
    }
    case DType::I32: {
        const i32 v = (i32)RdLE(data, 4);
        snprintf(buf, sizeof(buf), "%d", (int)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 4;
        return tv;
    }
    case DType::U32: {
        const u32 v = (u32)RdLE(data, 4);
        snprintf(buf, sizeof(buf), "%u", (unsigned)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 4;
        return tv;
    }
    case DType::I64: {
        const i64 v = (i64)RdLE(data, 8);
        snprintf(buf, sizeof(buf), "%lld", (long long)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 8;
        return tv;
    }
    case DType::U64: {
        const u64 v = RdLE(data, 8);
        snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 8;
        return tv;
    }
    case DType::F32: {
        float f = 0.f;
        const u32 bits = (u32)RdLE(data, 4);
        std::memcpy(&f, &bits, 4);
        tv.value = FmtFloat((double)f, 6);
        tv.ok = true; tv.usedBytes = 4;
        return tv;
    }
    case DType::F64: {
        double d = 0.0;
        const u64 bits = RdLE(data, 8);
        std::memcpy(&d, &bits, 8);
        tv.value = FmtFloat(d, 12);
        tv.ok = true; tv.usedBytes = 8;
        return tv;
    }
    case DType::Bool:
        tv.value = data[0] ? "true" : "false";
        tv.ok = true; tv.usedBytes = 1;
        return tv;

    case DType::Bit: {
        const int bit = (int)((data[0] >> bitIndex) & 1);
        tv.value = bit ? "true" : "false";
        tv.note = "bit " + std::to_string(bitIndex) + "/0-7";
        tv.ok = true; tv.usedBytes = 1;
        return tv;
    }

    case DType::StrA: {
        // NUL'a kadar ilerle; kontrol-disi baytlar '?' olur
        std::string out;
        size_t used = 0;
        const size_t cap = std::min<size_t>(avail, maxChars * 4);
        for (; used < cap; used++) {
            const u8 c = data[used];
            if (c == 0) { used++; break; }           // NUL tuketilir
            out.push_back((c >= 0x20 && c < 0x7F) ? (char)c : '?');
        }
        tv.value = out;
        tv.ok = true;
        tv.usedBytes = used;
        if (used >= cap && used > 0 && data[used - 1] != 0)
            tv.note = "NUL bulunamadi, kisaltildi";
        return tv;
    }

    case DType::StrW: {
        // UTF-16LE ciftleri 0x0000'a kadar (surrogate ciftleri dahil)
        std::vector<u16> wide;
        size_t used = 0;
        const size_t capBytes = std::min<size_t>(avail, maxChars * 4);
        while (used + 1 < capBytes) {
            const u16 ch = (u16)(data[used] | ((u16)data[used + 1] << 8));
            used += 2;
            if (ch == 0) break;
            wide.push_back(ch);
        }
        tv.value = str::WideToUtf8(wide.data(), wide.size());
        tv.ok = true;
        tv.usedBytes = used;
        if (used + 1 >= capBytes && !wide.empty() && wide.back() != 0)
            tv.note = "NUL bulunamadi, kisaltildi";
        return tv;
    }

    case DType::Ptr: {
        const u64 v = RdLE(data, 8);
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
        tv.value = buf; tv.ok = true; tv.usedBytes = 8;
        return tv;
    }

    case DType::Vec2:
    case DType::Vec3:
    case DType::Vec4: {
        const int n = (int)sz / 4;
        std::string out;
        for (int k = 0; k < n; k++) {
            const u32 bits = (u32)RdLE(data + (size_t)k * 4, 4);
            float f = 0.f;
            std::memcpy(&f, &bits, 4);
            if (k) out += ", ";
            out += FmtFloat((double)f, 6);
        }
        tv.value = out; tv.ok = true; tv.usedBytes = sz;
        return tv;
    }

    default:
        tv.note = "bilinmeyen tip";
        return tv;
    }
}

// ============================================================================
// encode: deger -> bayt (arama / yama)
// ============================================================================
bool DataType::Encode(DType t, const std::string& input, std::vector<u8>& out,
                      std::string& err) {
    out.clear();
    const std::string s = str::Trim(input);
    if (s.empty()) { err = "bos deger"; return false; }

    // tamsayilar
    if (IsInteger(t)) return EncodeInt(t, s, out, err);

    switch (t) {
    case DType::F32: {
        errno = 0;
        char* end = nullptr;
        const float v = std::strtof(s.c_str(), &end);
        if (end == s.c_str() || (end && *end != '\0')) { err = "gecersiz float: " + s; return false; }
        u32 bits = 0;
        std::memcpy(&bits, &v, 4);
        WrLE(out, bits, 4);
        return true;
    }
    case DType::F64: {
        errno = 0;
        char* end = nullptr;
        const double v = std::strtod(s.c_str(), &end);
        if (end == s.c_str() || (end && *end != '\0')) { err = "gecersiz double: " + s; return false; }
        u64 bits = 0;
        std::memcpy(&bits, &v, 8);
        WrLE(out, bits, 8);
        return true;
    }
    case DType::Bool: {
        const std::string l = str::Lower(s);
        if (l == "1" || l == "true" || l == "on" || l == "yes") out.push_back(0x01);
        else if (l == "0" || l == "false" || l == "off" || l == "no") out.push_back(0x00);
        else { err = "bool girdisi: 1/0/true/false"; return false; }
        return true;
    }
    case DType::Bit:
        err = "bit aramasi tek bayt icinde anlamli degildir; bool: kullanin";
        return false;

    case DType::StrA:
        for (char c : s) out.push_back((u8)c);
        return true;

    case DType::StrW:
        // BMP-ASCII: karakter basina (byte, 0x00) — text16: davranisiyla ayni
        if (s.size() < 2) { err = "str16 en az 2 karakter gerekli"; return false; }
        for (char c : s) {
            out.push_back((u8)c);
            out.push_back(0x00);
        }
        return true;

    case DType::Ptr: {
        unsigned long long v;
        if (!ParseUnsignedU64(s, v, err)) return false;
        WrLE(out, v, 8);
        return true;
    }

    case DType::Vec2:
    case DType::Vec3:
    case DType::Vec4: {
        // "1 2 3" / "1, 2, 3" / "1;2;3" -> N adet float
        std::vector<std::string> parts;
        std::string cur;
        for (char c : s) {
            if (c == ' ' || c == ',' || c == ';' || c == '\t') {
                if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
            } else cur.push_back(c);
        }
        if (!cur.empty()) parts.push_back(cur);
        const int n = (int)SizeOf(t) / 4;
        if ((int)parts.size() != n) {
            err = Name(t) + std::string(" icin ") + std::to_string(n) + " float gerekli (\"1 2 3\")";
            return false;
        }
        for (const std::string& p : parts) {
            errno = 0;
            char* end = nullptr;
            const float f = std::strtof(p.c_str(), &end);
            if (end == p.c_str() || (end && *end != '\0')) { err = "gecersiz float: " + p; return false; }
            u32 bits = 0;
            std::memcpy(&bits, &f, 4);
            WrLE(out, bits, 4);
        }
        return true;
    }

    default:
        err = "tip encode desteklemiyor";
        return false;
    }
}

// ============================================================================
// tipli sorgu on ekleri: "f32:3.14" -> bayt deseni
// ============================================================================
bool DataType::TryTypedQuery(const std::string& queryRaw, std::vector<u8>& bytes,
                             std::vector<bool>& wildcard, std::string& err) {
    const std::string q = str::Trim(queryRaw);
    if (q.empty()) return false;

    const size_t colon = q.find(':');
    if (colon == std::string::npos || colon == 0) return false;

    // bas-bosluk yoksa AOB tokenlari da ':' icermez; baslik tip adi olmali
    const std::string head = str::Lower(str::Trim(q.substr(0, colon)));
    DType t = DType::U8;
    if (!FromName(head, t)) return false;

    const std::string value = str::Trim(q.substr(colon + 1));
    if (!Encode(t, value, bytes, err)) return false;

    wildcard.assign(bytes.size(), false);
    err.clear();
    return true;
}

// ============================================================================
// tip listesi
// ============================================================================
std::string DataType::TypeTable() {
    std::ostringstream o;
    o << "Tipler (little-endian):\n";
    o << "  i8/int8/sbyte            u8/uint8/byte\n";
    o << "  i16/int16/short          u16/uint16/ushort/word\n";
    o << "  i32/int32/int/dword      u32/uint32/uint\n";
    o << "  i64/int64                u64/uint64/qword\n";
    o << "  f32/float                f64/double\n";
    o << "  bool                     bit (bayt icinde bit 0..7)\n";
    o << "  str/string/ascii         str16/utf16/wide\n";
    o << "  ptr/pointer (8 bayt)     vec2 vec3(vec3d/fvector) vec4\n";
    return o.str();
}

} // namespace dumper
