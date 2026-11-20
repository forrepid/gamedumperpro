// ============================================================================
// DumperPro - Il2CppDummyDll.cpp
//
// Derlenebilir C# kaynak stub uretimi (Il2CppDumper DummyDll paritesi).
// Semantik detaylar ust klasordeki Il2CppDummyDll.h yorumlarinda.
// Attribute semasi: Il2CppDumper DummyDll ciktisi ile ayni isimler
// (AddressAttribute / TokenAttribute / FieldOffsetAttribute).
// ============================================================================

#include "il2cpp/Il2CppDummyDll.h"
#include "utils/StrUtil.h"
#include "utils/Logger.h"

#include <unordered_set>

namespace dumper {

namespace {

// ---- C# isim duzenleme -------------------------------------------------------
// Il2CppDumper FixName ile ayni amac: gecersiz karakterler + anahtar kelimeler.
const char* const kCsKeywords[] = {
    "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char",
    "checked", "class", "const", "continue", "decimal", "default", "delegate",
    "do", "double", "else", "enum", "event", "explicit", "extern", "false",
    "finally", "fixed", "float", "for", "foreach", "goto", "if", "implicit",
    "in", "int", "interface", "internal", "is", "lock", "long", "namespace",
    "new", "null", "object", "operator", "out", "override", "params",
    "private", "protected", "public", "readonly", "ref", "return", "sbyte",
    "sealed", "short", "sizeof", "stackalloc", "static", "string", "struct",
    "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong",
    "unchecked", "unsafe", "ushort", "using", "var", "virtual", "void",
    "volatile", "while",
};

bool IsCsKeyword(const std::string& s) {
    for (const char* k : kCsKeywords)
        if (s == k) return true;
    return false;
}

std::string CsIdent(const std::string& raw) {
    std::string out = str::SanitizeIdent(raw);
    if (IsCsKeyword(out)) out = "@" + out;
    return out.empty() ? "_unnamed" : out;
}

// stub tip referansi: cozulemeyen/generic isimleri C# derlenebilir "object"e cevirir
std::string CsTypeRef(const std::string& resolved) {
    if (resolved.empty()) return "object";
    if (resolved.find('<') != std::string::npos) return "object";      // generic argumanlar
    if (resolved.find('?') != std::string::npos) return "object";
    if (resolved.find('!') != std::string::npos) return "object";      // VAR/MVAR
    if (str::StartsWith(resolved, "T<")) return "object";
    if (resolved.find("recursive") != std::string::npos) return "object";
    std::string s = resolved;
    if (str::EndsWith(s, "*") || str::EndsWith(s, "[]")) return "object"; // pointer/dizi stub'da object
    if (str::EndsWith(s, "ref ")) s = "object";
    if (str::StartsWith(s, "ref ")) return "object";
    if (str::StartsWith(s, "pinned ")) return "object";
    // noktali isimleri koru (System.Int32 gibi); geri kalan karakterler zaten alfanumerik
    return s;
}

std::string CsAccessField(u16 flags) {
    switch (flags & 0x7u) {
        case 6: return "public";
        case 4: return "protected";
        case 3: return "internal";
        default: return "private";
    }
}

std::string CsAccessMethod(u16 flags) {
    switch (flags & 0x7u) {
        case 6: return "public";
        case 4: return "protected";
        case 3: return "internal";
        default: return "private";
    }
}

std::string HexAttr(u64 v) {
    char b[32];
    snprintf(b, sizeof(b), "\"0x%llX\"", (unsigned long long)v);
    return b;
}

std::string HexAttr32(u32 v) {
    char b[24];
    snprintf(b, sizeof(b), "\"0x%08X\"", v);
    return b;
}

std::string CsStringLit(const std::string& in) {
    // C# duz dizgi icinde guvenli bicim
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char ch : in) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) out += ' ';
                else out += (char)ch;
        }
    }
    return out;
}

} // namespace

// ============================================================================
// _attributes.cs - Il2CppDummyDll attribute semasi
// ============================================================================
std::string Il2CppDummyDll::BuildAttributesCs() {
    std::string o;
    o += "// DumperPro DummyDll attribute tanimlari\n";
    o += "// Il2CppDumper DummyDll semasi ile ayni isimler (dnSpy uyumlu).\n";
    o += "// Bu dosya uretim yoneticisi tarafindan otomatik uretilmistir.\n";
    o += "namespace Il2CppDummyDll\n{\n";
    o += "    [global::System.AttributeUsage(global::System.AttributeTargets.All, AllowMultiple = false)]\n";
    o += "    public class AddressAttribute : global::System.Attribute\n    {\n";
    o += "        public string RVA { get; set; }\n";
    o += "        public string Offset { get; set; }\n";
    o += "        public string VA { get; set; }\n";
    o += "    }\n\n";
    o += "    [global::System.AttributeUsage(global::System.AttributeTargets.All, AllowMultiple = false)]\n";
    o += "    public class TokenAttribute : global::System.Attribute\n    {\n";
    o += "        public string Token { get; set; }\n";
    o += "    }\n\n";
    o += "    [global::System.AttributeUsage(global::System.AttributeTargets.Field, AllowMultiple = false)]\n";
    o += "    public class FieldOffsetAttribute : global::System.Attribute\n    {\n";
    o += "        public string Offset { get; set; }\n";
    o += "    }\n";
    o += "}\n";
    return o;
}

std::string Il2CppDummyDll::BuildReadmeTxt() {
    std::string o;
    o += "DumperPro - DummyDll (kaynak duzeyi, Il2CppDumper paritesi)\n";
    o += "============================================================\n\n";
    o += "Bu klasor image basina DERLENEBILIR C# kaynak dosyalari icerir.\n";
    o += "Derleyerek Il2CppDumper'in DummyDll ciktiyla ayni amaca hizmet eden\n";
    o += ".NET assembly'leri elde edersiniz: dnSpy/ILSpy'da tipler, alanlar,\n";
    o += "metodlar; [Address]/[Token]/[FieldOffset] attribute'lari ile.\n\n";
    o += "Derleme (Windows, .NET Framework / Roslyn csc):\n";
    o += "  build.bat                       (her image icin ayri DLL)\n\n";
    o += "Elle derleme:\n";
    o += "  csc /nologo /target:library /out:MyGame.dll _attributes.cs MyGame.dll.cs\n\n";
    o += "dotnet SDK ile:\n";
    o += "  her .cs icin ayri classlib projesi olusturup _attributes.cs ile derleyin.\n\n";
    o += "Bilincli kisaltmalar:\n";
    o += "  - metod govdele bos (stub)\n";
    o += "  - enum degerleri 0..n (metadata default-values parse edilmez)\n";
    o += "  - cozulemeyen tip referanslari object olur\n";
    o += "  - generic tipler non-generic stub olarak cikar\n\n";
    o += "YASAL SINIR: Yalnizca sahibi olunan/lisansli yazilimin analizi icin.\n";
    o += "Cok oyunculu hile amacli kullanim kapsam disidir (README DISCLAIMER).\n";
    return o;
}

std::string Il2CppDummyDll::BuildBuildBat(const std::vector<std::string>& imageFiles) {
    std::string o;
    o += "@echo off\r\n";
    o += "rem DumperPro DummyDll derleme scripti (Il2CppDumper paritesi)\r\n";
    o += "rem Gereksinim: csc (Visual Studio / .NET Framework / Build Tools)\r\n";
    o += "setlocal\r\n";
    o += "set OUTDIR=%~dp0compiled\r\n";
    o += "if not exist \"%OUTDIR%\" mkdir \"%OUTDIR%\"\r\n";
    o += "set CSC=csc.exe\r\n";
    o += "where %CSC% >nul 2>nul\r\n";
    o += "if errorlevel 1 (\r\n";
    o += "  echo csc.exe bulunamadi. Visual Studio \"Developer Command Prompt\" icinde calistirin.\r\n";
    o += "  exit /b 1\r\n";
    o += ")\r\n";
    o += "cd /d \"%~dp0\"\r\n";
    for (const std::string& f : imageFiles) {
        const std::string base = f.substr(0, f.find(".cs"));
        o += "%CSC% /nologo /nowarn:0219,0169 /target:library /out:\"%OUTDIR%" +
             base + ".dll\" _attributes.cs \"" + f + "\"\r\n";
    }
    o += "echo Bitti. DLL'ler: %OUTDIR%\r\n";
    o += "endlocal\r\n";
    return o;
}

// ============================================================================
// image basina C# kaynak
// ============================================================================
std::string Il2CppDummyDll::BuildImageCs(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                         const std::string& imageName, u32 imageIndex,
                                         const u8* binData, size_t binSize) {
    const Il2ImageInfo* img = nullptr;
    if (imageIndex < meta.images.size()) img = &meta.images[imageIndex];

    std::string o;
    o.reserve(2 << 20);
    o += "// DumperPro DummyDll kaynak: " + imageName + "\n";
    o += "// metadata surumu: " + meta.versionStr +
         (meta.unityHint.empty() ? "" : "  (" + meta.unityHint + ")") + "\n";
    o += "// Stub: govdesiz metodlar; adresler [Address] attribute'unda.\n";
    o += "// YASAL: yalnizca sahibi olunan/lisansli yazilimin analizi.\n\n";
    o += "using Il2CppDummyDll;\n\n";
    o += "#pragma warning disable 0219, 0169, 0649\n\n";

    // image'e ait tipler (nested dahil: image.typeStart..+typeCount)
    const u32 tStart = img ? img->typeStart : 0;
    const u32 tEnd = img ? img->typeStart + img->typeCount : 0;
    if (!img || tStart >= tEnd) {
        o += "// (bu image'de tip tanimi yok)\n";
        return o;
    }

    // ayni namespace'te tekrar eden tip isimlerini tekillestir
    std::unordered_set<std::string> usedTypeNames;

    auto MethodAddrAttr = [&](u32 globalMethodIdx) -> std::string {
        auto it = bin.methodAddresses.find(globalMethodIdx);
        if (it == bin.methodAddresses.end()) return "";
        char b[160];
        snprintf(b, sizeof(b), "    [Address(RVA = %s, Offset = %s, VA = %s)]\n",
                 HexAttr32(it->second.rva).c_str(),
                 it->second.fileOffset == 0xFFFFFFFFull ? "\"0x0\"" : HexAttr(it->second.fileOffset).c_str(),
                 HexAttr(it->second.va).c_str());
        return b;
    };

    for (u32 ti = tStart; ti < tEnd && ti < meta.types.size(); ti++) {
        const Il2TypeInfo& t = meta.types[ti];

        // --- tip adi + namespace ---
        std::string ns = t.ns;
        std::string tname = CsIdent(t.name.empty() ? ("Type_" + std::to_string(ti)) : t.name);
        // generic arity kalintisi (`1) SanitizeIdent ile alt cizgiye dondu; sonuna
        // tip indexini eklemeden tekrar edenleri tekillestir
        std::string unique = tname;
        int dup = 1;
        while (!usedTypeNames.insert(unique).second) {
            char b[16];
            snprintf(b, sizeof(b), "_%d", dup++);
            unique = tname + b;
        }
        tname = unique;

        const std::string kind = t.isEnum ? "enum" : (t.isInterface ? "interface" : (t.isValueType ? "struct" : "class"));

        // --- sinif acilisi ---
        o += "// TypeDefinition #" + std::to_string(ti) + "\n";
        if (!ns.empty()) o += "namespace " + CsIdent(ns) + "\n{\n";

        // kalitim: yalnizca class icin; enum/struct/interface kalitim yazilmaz
        std::string inherit;
        if (kind == "class" && t.parentIndex >= 0) {
            std::string parent = CsTypeRef(
                Il2CppBinaryMatch::ResolveTypeCSharpName(meta, bin, binData, binSize, t.parentIndex));
            if (parent != "object" && parent != "System.Object")
                inherit = " : " + parent;
        }
        o += "public " + kind + " " + tname + inherit + "\n{\n";

        // --- alanlar ---
        if (kind == "enum") {
            o += "    // degerler stub'ta 0..n (metadata default-values parse edilmiyor)\n";
            for (u32 k = 0; k < t.fieldCount && (u64)t.fieldStart + k < meta.fields.size(); k++) {
                const Il2FieldInfo& f = meta.fields[t.fieldStart + k];
                if (f.name.empty() || f.name == "value__") continue; // backing alan
                o += "    " + CsIdent(f.name) + ",\n";
            }
        } else {
            auto fit = bin.fieldOffsets.find(ti);
            for (u32 k = 0; k < t.fieldCount && (u64)t.fieldStart + k < meta.fields.size(); k++) {
                const Il2FieldInfo& f = meta.fields[t.fieldStart + k];
                std::string ftype = CsTypeRef(
                    Il2CppBinaryMatch::ResolveTypeCSharpName(meta, bin, binData, binSize, f.typeIndex));
                std::string off;
                if (fit != bin.fieldOffsets.end() && k < fit->second.size() && fit->second[k] > 0) {
                    char b[32];
                    snprintf(b, sizeof(b), "0x%02X", fit->second[k]);
                    o += "    [FieldOffset(Offset = \"" + std::string(b) + "\")]\n";
                }
                o += "    [Token(Token = " + HexAttr32(f.token) + ")]\n";
                o += "    " + CsAccessField(f.flags) + (f.flags & 0x10u ? " static" : "") +
                     " " + ftype + " " +
                     CsIdent(f.name.empty() ? ("field_" + std::to_string(k)) : f.name) + ";\n";
            }
        }

        // --- metodlar ---
        for (u32 k = 0; k < t.methodCount && (u64)t.methodStart + k < meta.methods.size(); k++) {
            const u32 g = t.methodStart + k;
            const Il2MethodInfo& mi = meta.methods[g];

            const std::string addrAttr = MethodAddrAttr(g);
            if (!addrAttr.empty()) o += addrAttr;
            o += "    [Token(Token = " + HexAttr32(mi.token) + ")]\n";

            std::string ret = CsTypeRef(
                Il2CppBinaryMatch::ResolveTypeCSharpName(meta, bin, binData, binSize, mi.returnTypeIndex));

            std::string mname = CsIdent(mi.name.empty() ? ("method_" + std::to_string(k)) : mi.name);
            if (mname == tname) mname += "_m"; // ctor ile cakisma

            std::string params;
            std::unordered_set<std::string> usedParams;
            for (u32 p = 0; p < mi.parameterCount; p++) {
                const u64 pi = (u64)mi.parameterStart + p;
                if (pi >= meta.params.size()) continue;
                const Il2ParamInfo& pr = meta.params[pi];
                if (p) params += ", ";
                std::string ptype = CsTypeRef(
                    Il2CppBinaryMatch::ResolveTypeCSharpName(meta, bin, binData, binSize, pr.typeIndex));
                std::string pname = CsIdent(pr.name.empty() ? ("p" + std::to_string(p)) : pr.name);
                while (!usedParams.insert(pname).second) pname += "_";
                params += ptype + " " + pname;
            }

            if (kind == "interface") {
                // C# interface metodlari erisim/static/virtual modifiyeli alamaz
                o += "    " + ret + " " + mname + "(" + params + ");\n";
            } else {
                o += "    " + CsAccessMethod(mi.flags) +
                     (mi.flags & 0x10u ? " static" : "") +
                     (kind == "class" && (mi.flags & 0x40u) ? " virtual" : "") +
                     " " + ret + " " + mname +
                     "(" + params + ")\n    {\n    }\n";
            }
        }

        // --- sinif kapanisi ---
        if (kind == "interface") o += "}\n";
        else o += "}\n";
        if (!ns.empty()) o += "}\n";
        o += "\n";
    }
    return o;
}

void Il2CppDummyDll::WriteOutputs(const Il2Metadata& meta, const Il2BinaryResult& bin,
                                  const fs::path& outDir,
                                  const u8* binData, size_t binSize) {
    const fs::path dllDir = outDir / "DummyDll";
    std::error_code ec;
    fs::create_directories(dllDir, ec);

    {
        std::ofstream f(dllDir / "_attributes.cs", std::ios::binary | std::ios::trunc);
        f << BuildAttributesCs();
    }
    {
        std::ofstream f(dllDir / "_readme.txt", std::ios::binary | std::ios::trunc);
        f << BuildReadmeTxt();
    }

    std::vector<std::string> imageFiles;
    for (u32 im = 0; im < meta.images.size(); im++) {
        const Il2ImageInfo& img = meta.images[im];
        if (img.typeCount == 0 && img.typeStart >= meta.types.size()) continue;
        const std::string safe = str::SanitizeIdent(img.name.empty()
                                        ? ("image_" + std::to_string(im)) : img.name);
        const std::string csName = safe + ".cs";
        const std::string src = BuildImageCs(meta, bin, img.name, im, binData, binSize);
        std::ofstream f(dllDir / csName, std::ios::binary | std::ios::trunc);
        f << src;
        imageFiles.push_back(csName);
    }
    {
        std::ofstream f(dllDir / "build.bat", std::ios::binary | std::ios::trunc);
        f << BuildBuildBat(imageFiles);
    }
    Log::Ok("DummyDll (kaynak stub) -> %s (%u image)", dllDir.string().c_str(), imageFiles.size());
}

} // namespace dumper
