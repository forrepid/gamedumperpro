// ============================================================================
// DumperPro - DataType.h
//
// MERKEZI VERI TIPI KAYIT SISTEMI (data type registry).
//
// Amaclar:
//   1) Bellek/dosya baytlarini tipli deger olarak yorumlamak (little-endian):
//        int8..int64, uint8..uint64, float/double, bool, bit,
//        ASCII + UTF-16LE string, pointer (u64), float vektorler (vec2..vec4)
//   2) Kullanici girdisini ("42", "3.14", "true", "Merhaba") tipin bayt
//      gosterimine cevirmek (deger arama + yama icin)
//   3) HexTool "--hex-type" tipli gorunumu ve "--hex-search" tipli sorgu
//      on eklerini beslemek (HexTool::ParseQuery ile entegre)
//
// Tip adlari (buyuk/kucuk harf duyarsiz; Cheat Engine / ReClass / UE dostu):
//   i8  int8  sbyte            u8  uint8  byte
//   i16 int16 short            u16 uint16 ushort word
//   i32 int32 int  dword       u32 uint32 uint
//   i64 int64                  u64 uint64 qword
//   f32 float float32          f64 double float64
//   bool boolean               bit
//   str string ascii           str16 utf16 wide wstring
//   ptr pointer                vec2 vector2d fvector2d
//                              vec3 vector3d fvector (UE FVector)
//                              vec4 vector4d fvector4, frotator (UE FRotator)
//
// Bayt siralamasi: tum tipler little-endian (x86/x64 Windows hedefi).
// Not: tip adlari olarak "text"/"text16" KULLANILMAZ; onlar HexTool'un
// klasik metin arama on ekleridir (text:, text16:) ve cakismamalidir.
// ============================================================================

#pragma once
#include "../framework.h"

namespace dumper {

// tipli deger yorumlama tipleri (little-endian)
enum class DType : int {
    I8, U8,     // 1 bayt
    I16, U16,   // 2 bayt
    I32, U32,   // 4 bayt
    I64, U64,   // 8 bayt
    F32,        // 4 bayt float (IEEE 754)
    F64,        // 8 bayt double
    Bool,       // 1 bayt bool (0 = false, 1 = true)
    Bit,        // 1 bayt icinde tek bit (bitIndex 0..7, 0 = LSB)
    StrA,       // ASCII/latin-1, NUL'a kadar (degisken)
    StrW,       // UTF-16LE, 0x0000'a kadar (degisken; FString/wchar uyumlu)
    Ptr,        // 8 bayt pointer -> hex gosterim
    Vec2,       // 2 x float (8 bayt)   "x, y"
    Vec3,       // 3 x float (12 bayt)  "x, y, z" (UE FVector / FRotator)
    Vec4,       // 4 x float (16 bayt)  "x, y, z, w"
    Count
};

// tek bir tipli deger yorumlama sonucu
struct TypedValue {
    DType type = DType::U8;
    bool ok = false;        // yeterli bayt var mi + yorumlandi mi
    std::string value;      // gorunum metni ("42", "3.14", "true", "0x7FF6...")
    std::string note;       // ek bilgi ("NUL bulunamadi", "eksik bayt", ...)
    size_t usedBytes = 0;   // tuketilen bayt (string: sonlandirici dahil)
};

class DataType {
public:
    // tip adi -> DType (alias'lar dahil, buyuk/kucuk harf duyarsiz).
    // basarisizsa false.
    static bool FromName(const std::string& name, DType& out);

    // kanonik tip adi ("i32", "f32", "vec3", ...)
    static const char* Name(DType t);

    // sabit bayt boyutu; StrA/StrW -> 0 (degisken uzunluk)
    static size_t SizeOf(DType t);

    static bool IsInteger(DType t) { return t >= DType::I8 && t <= DType::U64; }
    static bool IsFloat(DType t)   { return t == DType::F32 || t == DType::F64 ||
                                            (t >= DType::Vec2 && t <= DType::Vec4); }
    static bool IsString(DType t)  { return t == DType::StrA || t == DType::StrW; }
    static bool IsVector(DType t)  { return t >= DType::Vec2 && t <= DType::Vec4; }

    // bayt yorumlama (little-endian).
    //   data/avail : yorumlanacak baytlar (avail >= SizeOf(t) ise tam okunur)
    //   bitIndex   : DType::Bit icin 0..7 (0 = en dusuk anlamli bit/LSB)
    //   maxChars   : string tipler icin karakter siniri
    static TypedValue Decode(const u8* data, size_t avail, DType t,
                             int bitIndex = 0, size_t maxChars = 96);

    // kullanici girdisini tipin little-endian bayt gosterimine cevirir.
    //   tamsayi : "42", "-7", "0x2A"
    //   float   : "3.14", "-1.5e3"
    //   bool    : "1/0/true/false/on/off/yes/no"
    //   str     : ham ASCII baytlar; str16: karakter basina 2 bayt LE
    //   ptr     : "0x7FF6A1B2C3D4" (8 bayt LE)
    //   vecN    : "1 2 3" veya "1, 2, 3" (N adet float)
    //   bit     : arama/yama icin anlamli degil -> hata (bool kullanin)
    static bool Encode(DType t, const std::string& input, std::vector<u8>& out,
                       std::string& err);

    // "f32:3.14", "i32:1337", "u64:0x7FF6...", "bool:1", "str:Hello",
    // "str16:Selam", "vec3:1 2 3" sorgu on eklerini bayt desenine cevirir.
    // Eger sorgu bilinen bir tip on ekiyle BASLAMIYORSA false doner (err
    // bos kalir) ve cagiran AOB/hex yoluyla devam eder. Tip on eki taninip
    // deger gecersizse false + err dolu doner.
    static bool TryTypedQuery(const std::string& query, std::vector<u8>& bytes,
                              std::vector<bool>& wildcard, std::string& err);

    // tip listesi yardim metni (--help / --modules baglamsali)
    static std::string TypeTable();
};

} // namespace dumper
