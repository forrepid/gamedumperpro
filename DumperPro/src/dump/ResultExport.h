// DumperPro - Web entegrasyon ciktilari (motor -> web platformu koprusu, 0.5.0)
//
// functions.json : tum UE UFunction listesi (class/package/name/rva/va/params/flags)
// result.json    : kisal manifest (arac surumu, hedef, UE surumu, sayimlar, dosya listesi)
//
// Semalar web tarafindaki src/lib/dumperpro/parse.ts ile birebir eslesir:
//   {"format":"dumperpro-functions","version":1,...}
//   {"format":"dumperpro-result","version":1,...}
#pragma once
#include "../framework.h"
#include "ue/UEObject.h"

namespace dumper {

constexpr const char* kDumperProVersion = "0.5.0";

// Tek UFunction kaydi (UEContext'siz durabilen duz veri; unit-test edilebilir)
struct FuncJsonParam {
    std::string name;
    std::string type;        // "FloatProperty", "StructProperty", ...
    std::string target;      // referans adi (struct/class/enum; auxName), yoksa bos
    i32 offset = -1;         // Offset_Internal
    i32 size = 0;            // elementSize
    u64 flags = 0;           // EPropertyFlags
};

struct FuncJsonRec {
    std::string cls;         // sahibi UClass adi
    std::string pkg;         // en ust Outer (package) adi
    std::string name;        // fonksiyon adi
    u64 native = 0;          // UFunction::Func (native isaretci; BP-only -> 0)
    u64 ufunc = 0;           // UFunction nesnesi VA
    u32 paramsSize = 0;
    u64 flags = 0;           // EFunctionFlags
    bool rvaOk = false;      // native modul icindeyse true
    u64 rva = 0;
    std::vector<FuncJsonParam> params;
    bool hasRet = false;
    FuncJsonParam ret;
};

// GObjects uzerinden tum UClass'leri gez, her birinin fonksiyonlarini topla.
// Paket adi SDKGenerator::BuildPackages ile ayni kural: en ust Outer adi.
bool CollectFunctionsJson(UEContext& ctx, std::vector<FuncJsonRec>& out);

// functions.json yazar. true = dosya yazildi.
bool WriteFunctionsJson(const fs::path& file,
                        const std::vector<FuncJsonRec>& funcs,
                        const std::string& game,
                        const std::string& ueVer,
                        const std::string& moduleName,
                        u64 moduleBase);

// result.json manifest yazar. true = dosya yazildi.
struct ResultManifest {
    std::string mode;        // device | file | process | kernel
    std::string target;      // cihaz stringi / dosya yolu / proses adi
    std::string game;
    std::string ueVer;
    std::string moduleName;
    u64 moduleBase = 0;
    u64 moduleSize = 0;
    std::string status;      // full | names-only
    size_t namesCount = 0;
    size_t objectsCount = 0;
    size_t functionsCount = 0;
    std::vector<std::string> artifacts;
};
bool WriteResultManifest(const fs::path& file, const ResultManifest& m);

} // namespace dumper
