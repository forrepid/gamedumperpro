// ============================================================================
// DumperPro - Il2CppDummyDll.h
//
// DUMMY DLL URETIMI (Il2CppDumper paritesi - kaynak duzeyi).
//
// Il2CppDumper'in DummyDll ciktisi gercek .NET assembly'leri yazmak icin
// dnlib kullanir (Libraries/Il2CppDummyDll.dll). DumperPro bunun
// "kaynak duzeyi" karsiligini uretir: image basina DERLENEBILIR C# kaynak
// dosyalari; kullanici bunlari csc/dotnet ile derleyerek ayni isleve sahip
// Dummy DLL'ler elde eder (dnSpy/IDA/ILSpy'da tipler, alanlar, metodlar,
// token ve adres attribute'lari ile gorunur).
//
// Cikti (outDir/DummyDll/):
//   _attributes.cs   Il2CppDummyDll namespace'i: AddressAttribute,
//                    TokenAttribute, FieldOffsetAttribute (Il2CppDumper
//                    DummyDll semasiyla ayni isimler/alanlar)
//   <Image>.cs       image basina tipler: alanlar [FieldOffset], metodlar
//                    [Address]/[Token], gercek tip isimleri (typesResolved)
//   build.bat        her image icin ayri DLL derleme scripti (csc)
//   _readme.txt      kullanim + yasal sinir notlari
//
// Bilincli kisaltmalar (stub dogasi):
//   - metod govdele bos; enum degerleri metadata default-values tablosu
//     parse edilmedigi icin 0..n (Il2CppDumper gercek degerleri yazar)
//   - cozulemeyen tip referanslari "object" olur (T<idx> yazilmaz - C#
//     derlenebilirlik icin); generic tipler non-generic stub olarak cikar
//   - nested tipler namespace duzeyinde duzlestirilir
//
// ONEMLI NOTLAR:
//   1) Bu cikti yalnizca STATIC ANALIZ destegi icindir: il2cpp runtime'i
//      calistirmaz, adresleri degistirmez, hedef prosese dokunmaz.
//   2) Kullanim siniri: yalnizca sahibi olunan/lisansli yazilimin analizi
//      (README DISCLAIMER); cok oyunculu hile kapsam disidir.
// ============================================================================

#pragma once
#include "../framework.h"
#include "il2cpp/Il2Cpp.h"
#include "il2cpp/Il2CppBinary.h"

namespace dumper {

class Il2CppDummyDll {
public:
    // outDir/DummyDll altina ciktilari yazar (bkz. ust yorum)
    static void WriteOutputs(const Il2Metadata& meta, const Il2BinaryResult& bin,
                             const fs::path& outDir,
                             const u8* binData = nullptr, size_t binSize = 0);

    // ayri uretimler (test/bakis icin)
    static std::string BuildAttributesCs();
    static std::string BuildReadmeTxt();
    static std::string BuildBuildBat(const std::vector<std::string>& imageFiles);
    static std::string BuildImageCs(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                    const std::string& imageName, u32 imageIndex,
                                    const u8* binData, size_t binSize);
};

} // namespace dumper
