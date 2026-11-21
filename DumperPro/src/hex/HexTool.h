// ============================================================================
// DumperPro - HexTool.h
//
// LIVE CODE / HEX / BYTE / BINARY / AOB VIEW-EDITOR-SAVE SISTEMI.
//
// Veri kaynaklari:
//   - Dosya modu : exe/dll/so/metadata ... tamami bellege (cap 1 GiB)
//   - Canli mod  : --process/--pid ile baglanan prosesin bir modul bolgesi
//                  (IMemoryReader uzerinden okunur; yamalar Write ile uygulanir)
//
// Yetenekler (view):
//   - Hex view     : offset + hex + ASCII tablo (klasik hex editor bicimi)
//   - Byte view    : ham bayt listesi (ayrilmis satirlar)
//   - Binary view  : bit duzeyinde (01001000 ...) ikilik gosterim
//   - Code view    : x86/x64 kaba (heuristic) uzunluk cozumlu ayristirici;
//                    bilinen opkodlarda mnemonik + rip-goreli hedef VA,
//                    bilinmeyenlerde "db 0x.." fallback. Tam kapasiteli bir
//                    ayristirici DEGILDIR (IDA/Capstone degil); imza yapimi,
//                    yol haritasi (jump table) okuma ve yama oncesi inceleme
//                    icin tasarlanmistir.
//
// Yetenekler (search - AOB + tipli deger):
//   - "48 8B 05 ?? ?? ?? ?? 48 85 C0" biciminde jokerli AOB ('??' / '?' joker)
//   - bosluksuz hex ("488B05????????") ve "text:Merhaba" ASCII aramasi
//   - tipli deger aramasi (little-endian): "f32:3.14", "i32:1337", "u64:0x7FF6",
//     "bool:1", "str:Merhaba", "str16:Selam", "vec3:1 2 3" (DataType modulu)
//   - tum eslesmeler (cap ile), mutlak VA + kaynak offset raporlanir
//
// Yetenekler (view - tipli deger):
//   - RenderTyped: ofsetten itibaren N adet degist tipli yorum (float/int/
//     bool/str/ptr/vec...); her satir VA + ham bayt + deger
//
// Yetenekler (edit/save):
//   - Patch: buffer'a yama; her yama undo yiginina kaydedilir
//   - Undo: son yamayi geri al (tanimliyorsa eski baytlar geri yazilir)
//   - SaveToFile: yamali kopyayi YENI dosyaya yazar (orijinal korunur)
//   - ApplyLive: canli modda tum yamalari IMemoryReader::Write ile hedefe
//     yazar (Windows'ta WriteProcessMemory; KernelReader yazmayi desteklemez)
//
// ONEMLI NOTLAR:
//   1) Canli yama (ApplyLive) calisan bir prosesin belleğini degistirir.
//      Yalnizca sahibi olunan/analiz yetkisi olan tek oyunculu yazilimlarda
//      ve arastirma amacli kullanin; cok oyunculu hile kapsam disidir
//      (README DISCLAIMER). Tool varsayilan olarak yama yapmaz: --hex-patch
//      ancak --hex-save veya --hex-live ile birlikte verildiginde etkilidir.
//   2) Tum okumalar/yamalar sinir kontrolludur: aralik disi offset reddedilir.
//   3) Bu modül motor yapmaz (no auto-AOB-generation); kullanici AOB girer.
// ============================================================================

#pragma once
#include "../framework.h"
#include "core/MemoryReader.h"
#include "core/DataType.h"

namespace dumper {

struct HexSearchHit {
    u64 offset = 0;     // buffer icindeki ofset
    u64 addr = 0;       // baseAddr + offset (VA/VA-goreli)
};

struct HexPatchRecord {
    u64 offset = 0;
    std::vector<u8> oldBytes;
    std::vector<u8> newBytes;
};

class HexTool {
public:
    // ---- kaynaklar ----
    // dosya tamami bellege (cap 1 GiB)
    static std::unique_ptr<HexTool> OpenFile(const fs::path& file);
    // canli prosesin bir modul bolgesi (base..base+size)
    static std::unique_ptr<HexTool> OpenLive(IMemoryReader& reader, const ModuleInfo& mod);
    // ozel aralik (base + len) - modul disinda bolgeler icin
    static std::unique_ptr<HexTool> OpenLiveRange(IMemoryReader& reader, u64 base, u64 len,
                                                  const std::string& label);

    bool OK() const { return ok_; }
    std::string LastError() const { return lastErr_; }
    bool IsLive() const { return live_; }
    const std::string& Label() const { return label_; }
    u64 BaseAddr() const { return baseAddr_; }
    size_t Size() const { return data_.size(); }

    // canli mod: bolgeyi prosesden yeniden okur (yamalar kaybolur)
    bool Reload(std::string& err);

    // ---- VIEW ----
    // klasik hex tablo: "00007FF6ABCD1000  48 8B 05 ...  |ascii|"
    std::string RenderHex(u64 offset, size_t rows, size_t bytesPerRow = 16) const;
    // x86/x64 kod gorunumu (bits: 64 veya 32)
    std::string RenderCode(u64 offset, size_t rows, int bits) const;
    // bit duzeyinde ikilik gosterim
    std::string RenderBinary(u64 offset, size_t bytes) const;
    // tipli deger gorunumu: ofsetten itibaren count adet degist tip yorumu
    // (satir: VA + ham bayt + [tip] deger). bitIndex: DType::Bit icin 0..7.
    std::string RenderTyped(u64 offset, DType type, size_t count,
                            int bitIndex = 0) const;

    // ---- SEARCH (AOB / hex / text) ----
    // sorgu bicimleri:
    //   "48 8B 05 ?? ?? ?? ??"  jokerli AOB
    //   "488B05????????"        bosluksuz AOB
    //   "text:GameAssembly"     ASCII metin aramasi
    //   "f32:3.14" / "i32:1337" / "bool:1" / "str:..." / "vec3:1 2 3"
    //                           tipli deger aramasi (DataType::TryTypedQuery)
    static bool ParseQuery(const std::string& query, std::vector<u8>& bytes,
                           std::vector<bool>& wildcard, std::string& err);
    std::vector<HexSearchHit> Search(const std::vector<u8>& bytes,
                                     const std::vector<bool>& wildcard,
                                     size_t maxHits = 4096) const;

    // ---- EDIT ----
    bool Patch(u64 offset, const std::vector<u8>& bytes, std::string& err);
    bool CanUndo() const { return !undo_.empty(); }
    bool Undo(std::string& err);
    size_t PatchCount() const { return patches_.size(); }
    const std::vector<HexPatchRecord>& Patches() const { return patches_; }

    // ---- SAVE ----
    // dosya modu: yamali buffer'i yeni dosyaya yazar (orijinal korunur)
    bool SaveToFile(const fs::path& out, std::string& err) const;
    // canli mod: tum yamalari Write() ile hedef prosese uygular
    bool ApplyLive(IMemoryReader& reader, std::string& err);

private:
    HexTool() = default;
    bool ok_ = false;
    bool live_ = false;
    std::string label_;
    u64 baseAddr_ = 0;
    std::vector<u8> data_;
    std::vector<HexPatchRecord> undo_;
    std::vector<HexPatchRecord> patches_;
    std::string lastErr_;
};

} // namespace dumper
