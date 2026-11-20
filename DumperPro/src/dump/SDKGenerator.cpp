// ============================================================================
// DumperPro - full C++ SDK generator
//
// Produces a Dumper-7 style SDK under opt_.outDir (e.g. <out>/SDK/):
//   _basics.hpp          minimal type stubs used by every generated header
//   <Package>_enums.h    enum class definitions
//   <Package>_structs.h  UScriptStruct definitions
//   <Package>_classes.h  UClass definitions
//   SDK.hpp              master include (_basics + every package, in order)
//   funcs.txt            native function addresses (sorted)
//
// Package grouping: every object belongs to the package named after the
// top-most object of its Outer chain. All reads are guarded; chain walks and
// property counts are capped.
// ============================================================================

#include "dump/SDKGenerator.h"
#include "ue/ObjectArray.h"
#include "core/MemoryReader.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"
#include "utils/Progress.h"

namespace dumper {

namespace {

constexpr size_t kMaxProps = 20000; // hard cap per object (properties / params / enum values)
constexpr int    kMaxHops  = 64;    // hard cap for Outer / Super chain walks
constexpr int    kMaxNest  = 8;     // hard cap for nested container type resolution

// ----------------------------------------------------------------------------
// small formatting helpers
// ----------------------------------------------------------------------------

// width-controlled hex: HexW(0x30, 2) -> "0x30", HexW(0x1234, 4) -> "0x1234"
std::string HexW(u64 v, int width) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%0*llX", width, (unsigned long long)v);
    return buf;
}

// EPropertyFlags name list for parameter comments: [OutParm|ReturnParm|...]
std::string PropFlagNames(u64 flags) {
    std::string out;
    const auto add = [&](const char* name, u64 bit) {
        if (flags & bit) {
            if (!out.empty()) out += "|";
            out += name;
        }
    };
    add("OutParm",    UEOffsets::CPF_OutParm);
    add("ReturnParm", UEOffsets::CPF_ReturnParm);
    add("ConstParm",  UEOffsets::CPF_ConstParm);
    add("Parm",       UEOffsets::CPF_Parm);
    return out.empty() ? std::string("none") : out;
}

// property type names understood by CppTypeFor (lowercase); everything else is
// emitted as uint8 with an "unhandled property type" note
const std::set<std::string>& KnownPropTypes() {
    static const std::set<std::string> s = {
        "objectproperty", "classproperty", "weakobjectproperty", "lazyobjectproperty",
        "softobjectproperty", "interfaceproperty", "structproperty", "arrayproperty",
        "setproperty", "mapproperty", "enumproperty", "byteproperty", "boolproperty",
        "floatproperty", "doubleproperty", "intproperty", "int64property", "int16property",
        "int8property", "uint32property", "uint64property", "uint16property", "strproperty",
        "nameproperty", "textproperty", "delegateproperty", "multicastdelegateproperty",
        "multicastinlinedelegateproperty", "multicastsparsedelegateproperty",
    };
    return s;
}

// ----------------------------------------------------------------------------
// package file naming: "<SanitizedPackage>_enums.h" etc.
// Two packages whose sanitized names collide get a "_<position>" suffix so
// every package maps to a unique file set (deterministic, order independent).
// ----------------------------------------------------------------------------
std::string PackageFileBase(const std::vector<std::string>& pkgNames, size_t idx) {
    const std::string base = str::SanitizeIdent(pkgNames[idx]);
    for (size_t j = 0; j < pkgNames.size(); j++) {
        if (j == idx) continue;
        if (str::SanitizeIdent(pkgNames[j]) == base) return base + "_" + std::to_string(idx);
    }
    return base;
}

// per-file banner shared by every generated header
void WriteFileBanner(std::ostream& os, const std::string& pkgName, const char* kind, size_t objectCount) {
    os << "// DumperPro SDK - " << pkgName << " (" << kind << ") - generated, do not edit\n";
    os << "// Objects: " << objectCount << "\n";
    os << "// Note: include SDK.hpp first to resolve cross-package references.\n";
    os << "#pragma once\n\n";
    os << "#include \"_basics.hpp\"\n\n";
}

// sink for funcs.txt lines; the fixed SDKGenerator interface has no parameter
// slot for it between GeneratePackage() and WriteFuncsTxt(), so the generator
// keeps one module-local vector (single-threaded generation).
std::vector<std::string>& FuncsSink() {
    static std::vector<std::string> lines;
    return lines;
}

} // namespace

// ============================================================================
// Generate - top level flow
// ============================================================================

bool SDKGenerator::Generate() {
    if (!ctx_.objects || !ctx_.objects->IsReady()) {
        Log::Err("SDK: object array not available");
        return false;
    }

    std::error_code ec;
    fs::create_directories(opt_.outDir, ec);
    if (ec) {
        Log::Err("SDK: cannot create output directory %s (%s)",
                 opt_.outDir.string().c_str(), ec.message().c_str());
        return false;
    }
    const fs::path sdkDir = opt_.outDir;

    // ---- package grouping ----
    BuildPackages();

    size_t totalObjects = 0;
    for (const PackageInfo& p : packages_) totalObjects += p.objIndices.size();
    Log::Info("SDK: %llu packages, %llu objects",
              (unsigned long long)packages_.size(), (unsigned long long)totalObjects);

    // ---- basics stubs ----
    EmitBasics(sdkDir);
    size_t fileCount = 1; // _basics.hpp

    // ---- per package pass ----
    FuncsSink().clear();
    const size_t kindsPerPkg = (opt_.genEnums ? 1u : 0u) + (opt_.genStructs ? 1u : 0u) + (opt_.genClasses ? 1u : 0u);
    size_t failedPackages = 0;

    {
        Progress p("SDK", packages_.size());
        for (size_t i = 0; i < packages_.size(); i++) {
            if (GeneratePackage(packages_[i], i)) {
                fileCount += kindsPerPkg;
            } else {
                failedPackages++;
                Log::Warn("SDK: package '%s' failed", packages_[i].name.c_str());
            }
            p.Add();
        }

        // ---- master include + funcs.txt ----
        EmitMasterInclude(sdkDir);
        fileCount++;

        if (opt_.writeFuncsTxt) {
            WriteFuncsTxt(sdkDir, FuncsSink());
            fileCount++;
        }

        std::string note = std::to_string(fileCount) + " files";
        if (failedPackages) note += " - " + std::to_string(failedPackages) + " packages failed";
        p.Done(note);
    }

    Log::Ok("SDK generated: %llu files in %s", (unsigned long long)fileCount, sdkDir.string().c_str());
    return failedPackages == 0;
}

// ============================================================================
// BuildPackages - group object indices by top-most Outer name
// ============================================================================

void SDKGenerator::BuildPackages() {
    packages_.clear();

    ObjectArray* objs = ctx_.objects;
    if (!objs || !objs->IsReady()) return;

    const i32 num = objs->Num();
    if (num <= 0) return;

    // cache: object address -> package name (avoids re-walking Outer chains)
    std::unordered_map<u64, std::string> pkgByAddr;
    std::unordered_map<std::string, size_t> pkgIndexByName;
    pkgByAddr.reserve(4096);

    for (i32 i = 0; i < num; i++) {
        const u64 addr = objs->ObjectAt(i); // safe: zeroed on invalid index
        if (!addr) continue;

        UEObject obj(&ctx_, addr, i);
        if (obj.GetName().empty()) continue; // skip nameless objects

        // ---- resolve package name by walking the Outer chain (cached) ----
        std::string pkgName;
        const auto cached = pkgByAddr.find(addr);
        if (cached != pkgByAddr.end()) {
            pkgName = cached->second;
        } else {
            std::vector<u64> chain;
            std::unordered_set<u64> visited;
            u64 cur = addr;
            std::string top;
            for (int hops = 0; cur != 0 && hops < kMaxHops; hops++) {
                if (!visited.insert(cur).second) break; // cycle guard
                chain.push_back(cur);

                const auto hit = pkgByAddr.find(cur);
                if (hit != pkgByAddr.end()) { top = hit->second; break; }

                UEObject node(&ctx_, cur, -1);
                const u64 outer = node.GetOuter();
                if (!outer) { top = node.GetName(); break; } // top-most object
                cur = outer;
            }
            if (top.empty()) top = "Core"; // broken chain / unnamed root
            for (u64 a : chain) pkgByAddr.emplace(a, top);
            pkgName = top;
        }

        // ---- group (first-seen order preserved) ----
        size_t slot;
        const auto it = pkgIndexByName.find(pkgName);
        if (it == pkgIndexByName.end()) {
            PackageInfo info;
            info.name = pkgName;
            packages_.push_back(std::move(info));
            slot = packages_.size() - 1;
            pkgIndexByName.emplace(pkgName, slot);
        } else {
            slot = it->second;
        }
        packages_[slot].objIndices.push_back(i);
    }
}

// ============================================================================
// EmitBasics - _basics.hpp
// ============================================================================

void SDKGenerator::EmitBasics(const fs::path& sdkDir) {
    const fs::path file = sdkDir / "_basics.hpp";
    std::ofstream os(file, std::ios::binary | std::ios::trunc);
    if (!os.good()) {
        Log::Warn("SDK: cannot write %s", file.string().c_str());
        return;
    }

    os << "// ============================================================================\n";
    os << "// DumperPro SDK - _basics.hpp - generated, do not edit\n";
    os << "//\n";
    os << "// Minimal type stubs shared by every generated package header. Layouts are\n";
    os << "// approximations: they keep the SDK compilable and allow pointer-safe member\n";
    os << "// access, they do not match the engine byte-for-byte.\n";
    os << "// ============================================================================\n";
    os << "#pragma once\n";
    os << "\n";
    os << "#include <cstdint>\n";
    os << "#include <cstddef>\n";
    os << "\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "// Container stubs\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "\n";
    os << "template <class T>\n";
    os << "struct TArray\n";
    os << "{\n";
    os << "    T*      Data;\n";
    os << "    int32_t Num;\n";
    os << "    int32_t Max;\n";
    os << "\n";
    os << "    T&       operator[](int i)       { return Data[i]; }\n";
    os << "    const T& operator[](int i) const { return Data[i]; }\n";
    os << "};\n";
    os << "\n";
    os << "template <class K, class V> struct TMap;\n";
    os << "template <class T>          struct TSet;\n";
    os << "\n";
    os << "template <class T> struct TEnumAsByte     { T Value; };\n";
    os << "template <class T> struct TWeakObjectPtr;\n";
    os << "template <class T> struct TLazyObjectPtr;\n";
    os << "template <class T> struct TSoftObjectPtr;\n";
    os << "template <class T> struct TSubclassOf     { class UClass* ClassPtr; };\n";
    os << "template <class T> struct TScriptInterface;\n";
    os << "\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "// Core value types\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "\n";
    os << "struct FName\n";
    os << "{\n";
    os << "    int32_t Index;\n";
    os << "    int32_t Number;\n";
    os << "};\n";
    os << "\n";
    os << "struct FString\n";
    os << "{\n";
    os << "    TArray<wchar_t> Data;\n";
    os << "};\n";
    os << "\n";
    os << "// opaque engine types - given complete (approximate) stubs so that generated\n";
    os << "// members using them by value still compile\n";
    os << "struct FText                    { uint8 UnknownData[0x10]; };\n";
    os << "struct FScriptDelegate          { uint8 UnknownData[0x10]; };\n";
    os << "struct FMulticastScriptDelegate { uint8 UnknownData[0x10]; };\n";
    os << "\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "// Minimal UObject hierarchy\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "\n";
    os << "class UClass;\n";
    os << "class UFunction;\n";
    os << "\n";
    os << "class UObject\n";
    os << "{\n";
    os << "public:\n";
    os << "    void**         Vft;\n";
    os << "    uint32_t       ObjectFlags;\n";
    os << "    uint32_t       InternalIndex;\n";
    os << "    class UClass*  Class;\n";
    os << "    FName          Name;\n";
    os << "    class UObject* Outer;\n";
    os << "};\n";
    os << "\n";
    os << "class UFunction : public UObject {};\n";
    os << "class UClass : public UObject {};\n";
    os << "\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "// ProcessEvent entry point\n";
    os << "// ----------------------------------------------------------------------------\n";
    os << "\n";
    os << "// Implement by calling the native at UObject vtable slot 0x?? (see\n";
    os << "// vtable_funcs.txt) or the UFunction's Func pointer.\n";
    os << "void ProcessEvent(UObject* Object, UFunction* Function, void* Params);\n";

    os.flush();
    Log::Debug("_basics.hpp written");
}

// ============================================================================
// GeneratePackage - one <Package>_enums/_structs/_classes triple
// ============================================================================

bool SDKGenerator::GeneratePackage(const PackageInfo& pkg, size_t idx) {
    std::vector<std::string> names;
    names.reserve(packages_.size());
    for (const PackageInfo& p : packages_) names.push_back(p.name);
    const std::string base = PackageFileBase(names, idx);

    std::ofstream enumsOs, structsOs, classesOs;
    bool ok = true;

    if (opt_.genEnums) {
        const fs::path f = opt_.outDir / (base + "_enums.h");
        enumsOs.open(f, std::ios::binary | std::ios::trunc);
        if (!enumsOs.good()) {
            Log::Warn("SDK: cannot write %s", f.string().c_str());
            ok = false;
        } else {
            WriteFileBanner(enumsOs, pkg.name, "enums", pkg.objIndices.size());
        }
    }

    if (opt_.genStructs) {
        const fs::path f = opt_.outDir / (base + "_structs.h");
        structsOs.open(f, std::ios::binary | std::ios::trunc);
        if (!structsOs.good()) {
            Log::Warn("SDK: cannot write %s", f.string().c_str());
            ok = false;
        } else {
            WriteFileBanner(structsOs, pkg.name, "structs", pkg.objIndices.size());
        }
    }

    if (opt_.genClasses) {
        const fs::path f = opt_.outDir / (base + "_classes.h");
        classesOs.open(f, std::ios::binary | std::ios::trunc);
        if (!classesOs.good()) {
            Log::Warn("SDK: cannot write %s", f.string().c_str());
            ok = false;
        } else {
            WriteFileBanner(classesOs, pkg.name, "classes", pkg.objIndices.size());
        }
    }

    if (ok) {
        if (opt_.genEnums) EmitEnums(enumsOs, pkg);
        EmitStructsAndClasses(structsOs, classesOs, pkg);
        Log::Debug("SDK: package '%s' (%llu objects) -> %s_{enums,structs,classes}.h",
                   pkg.name.c_str(), (unsigned long long)pkg.objIndices.size(), base.c_str());
    }

    enumsOs.flush();
    structsOs.flush();
    classesOs.flush();
    return ok;
}

// ============================================================================
// EmitEnums
// ============================================================================

void SDKGenerator::EmitEnums(std::ostream& os, const PackageInfo& pkg) {
    bool first = true;

    for (const i32 idx : pkg.objIndices) {
        const u64 addr = ctx_.objects ? ctx_.objects->ObjectAt(idx) : 0;
        if (!addr) continue;

        UEObject o(&ctx_, addr, idx);
        if (!o.IsEnumObj()) continue;

        const std::string name = o.GetName();
        if (name.empty()) continue;

        std::vector<std::pair<std::string, int>> values = o.GetEnumValues();
        if (values.size() > kMaxProps) values.resize(kMaxProps);

        std::string fullPath = o.GetPathName();
        if (fullPath.empty()) fullPath = pkg.name + "." + name;

        if (!first) os << "\n";
        first = false;

        os << "// Enum " << fullPath << "\n";
        os << "enum class " << CppEnumName(name) << " : uint8\n";
        os << "{\n";

        const std::string pfxUnderscore = name + "_";
        const std::string pfxColon      = name + "::";
        std::set<std::string> seenMembers;

        for (size_t v = 0; v < values.size(); v++) {
            std::string m = values[v].first;
            // strip a leading "<EnumName>_" / "<EnumName>::" prefix when present
            if (str::StartsWith(m, pfxUnderscore)) {
                m = m.substr(pfxUnderscore.size());
            } else if (str::StartsWith(m, pfxColon)) {
                m = m.substr(pfxColon.size());
            }
            if (m.empty()) m = "Member_" + std::to_string(v);
            m = str::SanitizeIdent(m);
            for (int dup = 2; !seenMembers.insert(m).second; dup++) {
                m = str::SanitizeIdent(values[v].first) + "_" + std::to_string(dup);
            }
            os << "    " << m << " = " << values[v].second << ",\n";
        }

        os << "};\n";
    }
}

// ============================================================================
// EmitStructsAndClasses
// ============================================================================

void SDKGenerator::EmitStructsAndClasses(std::ostream& structsOs, std::ostream& classesOs, const PackageInfo& pkg) {
    if (!opt_.genStructs && !opt_.genClasses) return;

    for (const i32 idx : pkg.objIndices) {
        const u64 addr = ctx_.objects ? ctx_.objects->ObjectAt(idx) : 0;
        if (!addr) continue;

        UEObject o(&ctx_, addr, idx);

        const bool isClass  = o.IsClassObj();    // class name == "Class"
        const bool isStruct = o.IsStructObj();   // class name == "ScriptStruct"
        if (!isClass && !isStruct) continue;     // not a structure
        if (isClass && !opt_.genClasses) continue;
        if (isStruct && !opt_.genStructs) continue;

        const std::string name = o.GetName();
        if (name.empty()) continue;

        // ---- super + sizes ----
        std::string superName;
        u32 inheritedSize = 0;
        const u64 superAddr = o.GetSuper();
        if (superAddr) {
            UEObject sup(&ctx_, superAddr, -1);
            superName     = sup.GetName();
            inheritedSize = sup.GetPropertiesSize(); // 0 when no super / read failed
        }
        const bool superOk  = !superName.empty();
        const u32 totalSize = o.GetPropertiesSize();

        std::ostream& os = isClass ? classesOs : structsOs;

        // ---- header comment ----
        os << "// 0x0000 (0x" << HexW(totalSize, 4) << " - 0x" << HexW(inheritedSize, 4) << ")\n";
        os << (isClass ? "// Class " : "// ScriptStruct ") << pkg.name << "." << name << "\n";
        os << "// Size: 0x" << HexW(totalSize, 4) << " (inherited 0x" << HexW(inheritedSize, 4) << ")\n";

        // ---- declaration (undumpable super -> UObject / no base) ----
        if (isClass) {
            os << "class " << CppClassName(name) << " : public "
               << (superOk ? CppClassName(superName) : std::string("UObject")) << "\n";
        } else {
            os << "struct " << CppStructName(name);
            if (superOk) os << " : public " << CppStructName(superName);
            os << "\n";
        }
        os << "{\n";

        EmitMembers(os, o, inheritedSize);
        EmitFunctions(os, o, FuncsSink());

        os << "};\n\n";
    }
}

// ============================================================================
// EmitMembers - properties + padding fill
// ============================================================================

void SDKGenerator::EmitMembers(std::ostream& os, const UEObject& cls, u32 inheritedSize) {
    os << "public:\n";

    UEObject o = cls; // UEObject is a light handle (ctx/addr/index); methods are non-const
    std::vector<UEObject::Prop> props = o.GetProperties();
    if (props.size() > kMaxProps) props.resize(kMaxProps);

    // names already declared by any ancestor -> skip redefinitions
    std::set<std::string> ancestorNames;
    CollectAncestorNames(o, ancestorNames);

    std::vector<const UEObject::Prop*> own;
    std::set<std::string> seenCppNames;
    for (const UEObject::Prop& p : props) {
        if (p.offset < 0) continue;
        if (ancestorNames.count(p.name)) continue;
        if (!seenCppNames.insert(str::SanitizeIdent(p.name)).second) continue;
        own.push_back(&p);
    }
    if (own.empty()) return;

    std::stable_sort(own.begin(), own.end(),
        [](const UEObject::Prop* a, const UEObject::Prop* b) { return a->offset < b->offset; });

    u32 cursor = inheritedSize;
    for (const UEObject::Prop* pp : own) {
        const UEObject::Prop& p = *pp;
        const i64 off = p.offset;

        // gap between the last covered byte and this property
        if (off > (i64)cursor) {
            const u64 gap = (u64)off - cursor;
            os << "    uint8 UnknownData_" << HexW(cursor, 2) << "[0x" << HexW(gap, 2)
               << "]; // 0x" << HexW(cursor, 2) << "(0x" << HexW(gap, 2) << ")\n";
            cursor = (u32)off;
        }

        const std::string typeLow = str::Lower(str::Trim(p.type));
        const bool isBool = (typeLow == "boolproperty");
        u64 size;
        if (isBool) {
            size = p.arrayDim > 1 ? (u64)p.arrayDim : 1;
        } else {
            const u64 s = (u64)p.elementSize * (u64)(p.arrayDim > 1 ? p.arrayDim : 1);
            size = s ? s : 8; // unknown element size -> assume pointer sized
        }

        os << "    " << CppTypeFor(p) << " " << str::SanitizeIdent(p.name);
        if (p.arrayDim > 1) os << "[" << p.arrayDim << "]";

        if (isBool && p.arrayDim <= 1 && p.fieldMask != 0 && p.fieldMask != 0xFF) {
            os << " : 1; // 0x" << HexW(off, 2) << "(0x01) bitmask 0x"
               << HexW((u64)p.fieldMask, 2) << "\n";
        } else {
            os << "; // 0x" << HexW(off, 2) << "(0x" << HexW(size, 2) << ")";
            if (!p.type.empty() && !KnownPropTypes().count(typeLow)) {
                os << " unhandled property type: " << p.type;
            } else if (typeLow == "structproperty" && p.auxName.empty()) {
                os << " unresolved struct";
            }
            os << "\n";
        }

        cursor = (u32)off + (u32)size;
    }

    // trailing padding up to the declared total size
    const u32 totalSize = o.GetPropertiesSize();
    if (totalSize > cursor) {
        const u64 gap = (u64)totalSize - cursor;
        os << "    uint8 UnknownData_" << HexW(cursor, 2) << "[0x" << HexW(gap, 2)
           << "]; // 0x" << HexW(cursor, 2) << "(0x" << HexW(gap, 2) << ")\n";
    }
}

// ============================================================================
// EmitFunctions - parameter structs + declarations + funcs.txt lines
// ============================================================================

void SDKGenerator::EmitFunctions(std::ostream& os, const UEObject& cls, std::vector<std::string>& funcsLines) {
    if (!opt_.genFunctions) return;

    UEObject o = cls; // UEObject is a light handle (ctx/addr/index); methods are non-const
    std::vector<UEObject::Func> funcs = o.GetFunctions();
    if (funcs.empty()) return;
    if (funcs.size() > kMaxProps) funcs.resize(kMaxProps);

    const std::string clsCpp = o.IsClassObj() ? CppClassName(o.GetName())
                                              : CppStructName(o.GetName());
    std::set<std::string> seenFuncNames;

    for (const UEObject::Func& f : funcs) {
        if (f.name.empty()) continue;

        // unique C++ name within this class (memory junk can duplicate names)
        std::string fname = str::SanitizeIdent(f.name);
        std::string uniq  = fname;
        for (int dup = 2; !seenFuncNames.insert(uniq).second; dup++) {
            uniq = fname + "_" + std::to_string(dup);
        }

        // ---- parameters (the return property is reported separately) ----
        std::vector<const UEObject::Prop*> parms;
        for (const UEObject::Prop& p : f.params) {
            if (p.flags & UEOffsets::CPF_ReturnParm) continue;
            if (f.ret && p.addr == f.ret->addr) continue;
            parms.push_back(&p);
        }
        if (parms.size() > kMaxProps) parms.resize(kMaxProps);

        // render parameter text once; shared by Params struct and signature
        struct ParamText {
            std::string decl;
            std::string comment;
        };
        std::vector<ParamText> texts;
        texts.reserve(parms.size());

        std::set<std::string> seenParamNames;
        for (const UEObject::Prop* pp : parms) {
            const UEObject::Prop& p = *pp;
            const std::string raw = str::SanitizeIdent(p.name);
            std::string nm = raw;
            for (int dup = 2; !seenParamNames.insert(nm).second; dup++) {
                nm = raw + "_" + std::to_string(dup);
            }
            ParamText tx;
            tx.decl = CppTypeFor(p, /*forParam=*/true) + " " + nm;
            if (p.arrayDim > 1) tx.decl += "[" + std::to_string(p.arrayDim) + "]";
            tx.comment = " // 0x" + HexW((u64)(p.offset < 0 ? 0 : p.offset), 2)
                       + " (CPF flags: 0x" + HexW(p.flags, 8) + " ["
                       + PropFlagNames(p.flags) + "])";
            texts.push_back(std::move(tx));
        }

        std::string paramList;
        for (size_t i = 0; i < texts.size(); i++) {
            if (i) paramList += ", ";
            paramList += texts[i].decl;
        }

        os << "\n";

        // ---- params struct (only when the function takes parameters) ----
        if (!texts.empty()) {
            os << "    struct Params_" << uniq << "\n    {\n";
            for (size_t i = 0; i < texts.size(); i++) {
                os << "        " << texts[i].decl << ";" << texts[i].comment << "\n";
            }
            os << "    };\n";
        }

        // ---- declaration ----
        const std::string ret = f.ret ? CppTypeFor(*f.ret) : std::string("void");

        std::string addrText = "0x0"; // native address: RVA inside the module, else VA
        u64 rva = 0;
        bool rvaOk = false;
        if (f.nativeFunc != 0) {
            if (ctx_.mod && ctx_.mod->Contains(f.nativeFunc)) {
                rva = ctx_.mod->VaToRva(f.nativeFunc);
                rvaOk = true;
                addrText = HexW(rva, 6);
            } else {
                addrText = Hex(f.nativeFunc);
            }
        }

        os << "    " << ret << " " << uniq << "(" << paramList << "); // " << addrText
           << " | Params size: 0x" << HexW(f.paramsSize, 4)
           << " | Function flags: 0x" << HexW(f.flags, 8)
           << " | UFunction: " << Hex(f.addr)
           << " Native: " << Hex(f.nativeFunc) << "\n";

        // ---- funcs.txt entry ----
        std::string tag;
        if (opt_.vtResults) {
            const auto it = opt_.vtResults->find(f.name);
            if (it != opt_.vtResults->end() && it->second.found) {
                tag = "[" + (it->second.via.empty() ? std::string("vtable") : it->second.via) + "]";
            }
        }
        if (tag.empty()) tag = (f.nativeFunc != 0) ? "[pattern]" : "[ufunction]";

        funcsLines.push_back(clsCpp + "::" + uniq + " " + tag
            + " RVA " + (rvaOk ? HexW(rva, 6) : std::string("0x0"))
            + " VA " + Hex(f.nativeFunc)
            + " ParamsSize 0x" + HexW(f.paramsSize, 4)
            + " UFunction " + Hex(f.addr));
    }
}

// ============================================================================
// EmitMasterInclude - SDK.hpp
// ============================================================================

void SDKGenerator::EmitMasterInclude(const fs::path& sdkDir) {
    const fs::path file = sdkDir / "SDK.hpp";
    std::ofstream os(file, std::ios::binary | std::ios::trunc);
    if (!os.good()) {
        Log::Warn("SDK: cannot write %s", file.string().c_str());
        return;
    }

    os << "// DumperPro SDK - master include - generated, do not edit\n";
    os << "// Packages: " << packages_.size() << "\n";
    os << "// Include this file once; it pulls in the basic stubs and every package.\n";
    os << "#pragma once\n\n";
    os << "#include \"_basics.hpp\"\n";

    std::vector<std::string> names;
    names.reserve(packages_.size());
    for (const PackageInfo& p : packages_) names.push_back(p.name);

    for (size_t i = 0; i < packages_.size(); i++) {
        const std::string base = PackageFileBase(names, i);
        os << "\n// " << packages_[i].name << "\n";
        if (opt_.genEnums)   os << "#include \"" << base << "_enums.h\"\n";
        if (opt_.genStructs) os << "#include \"" << base << "_structs.h\"\n";
        if (opt_.genClasses) os << "#include \"" << base << "_classes.h\"\n";
    }

    os.flush();
    Log::Debug("SDK.hpp written (%llu packages)", (unsigned long long)packages_.size());
}

// ============================================================================
// WriteFuncsTxt
// ============================================================================

void SDKGenerator::WriteFuncsTxt(const fs::path& sdkDir, const std::vector<std::string>& lines) {
    if (!opt_.writeFuncsTxt) return;

    const fs::path file = sdkDir / "funcs.txt";
    std::ofstream os(file, std::ios::binary | std::ios::trunc);
    if (!os.good()) {
        Log::Warn("SDK: cannot write %s", file.string().c_str());
        return;
    }

    os << "// DumperPro funcs.txt - native addresses for functions referenced by the SDK\n";
    os << "// Format: <Class>::<Function> [tag] RVA 0x.. VA 0x.. ParamsSize 0x.. UFunction 0x..\n";
    os << "// Tags:   [vtable>...] resolved via vtable scan | [pattern] native pointer found | [ufunction] unresolved\n";
    os << "// Functions: " << lines.size() << "\n\n";

    std::vector<std::string> sorted = lines;
    std::sort(sorted.begin(), sorted.end());
    for (const std::string& l : sorted) os << l << "\n";

    os.flush();
    Log::Debug("funcs.txt written (%llu entries)", (unsigned long long)sorted.size());
}

// ============================================================================
// CppTypeFor - property type -> C++ type string
// ============================================================================

std::string SDKGenerator::CppTypeFor(const UEObject::Prop& p, bool forParam) {
    (void)forParam; // parameters use plain by-value semantics (Dumper-7 style)

    const std::string t = str::Lower(str::Trim(p.type));
    UEObject dummy(&ctx_, 0, -1); // ctx-only wrapper for inner property reads
    static int sNest = 0;         // single-threaded generation; guards recursion

    if (t == "objectproperty") {
        if (p.aux && !p.auxName.empty()) return "class " + CppClassName(p.auxName) + "*";
        return "class UObject*";
    }
    if (t == "classproperty") {
        if (p.aux && !p.auxName.empty()) return "class UClass* /*" + CppClassName(p.auxName) + "*/";
        return "class UClass*";
    }
    if (t == "weakobjectproperty") {
        const std::string inner = (p.aux && !p.auxName.empty()) ? CppClassName(p.auxName) : "UObject";
        return "TWeakObjectPtr<class " + inner + ">";
    }
    if (t == "lazyobjectproperty") {
        const std::string inner = (p.aux && !p.auxName.empty()) ? CppClassName(p.auxName) : "UObject";
        return "TLazyObjectPtr<class " + inner + ">";
    }
    if (t == "softobjectproperty") {
        const std::string inner = (p.aux && !p.auxName.empty()) ? CppClassName(p.auxName) : "UObject";
        return "TSoftObjectPtr<class " + inner + ">";
    }
    if (t == "interfaceproperty") {
        const std::string inner = (p.aux && !p.auxName.empty()) ? CppClassName(p.auxName) : "UObject";
        return "TScriptInterface<class " + inner + ">";
    }
    if (t == "structproperty") {
        return p.auxName.empty() ? "uint8" : CppStructName(p.auxName);
    }
    if (t == "arrayproperty") {
        UEObject::Prop inner;
        if (p.aux && sNest < kMaxNest && dummy.ReadPropertyAt(p.aux, inner)) {
            sNest++;
            const std::string r = "TArray<" + CppTypeFor(inner) + ">";
            sNest--;
            return r;
        }
        return "TArray<uint8>";
    }
    if (t == "setproperty") {
        UEObject::Prop inner;
        if (p.aux && sNest < kMaxNest && dummy.ReadPropertyAt(p.aux, inner)) {
            sNest++;
            const std::string r = "TSet<" + CppTypeFor(inner) + ">";
            sNest--;
            return r;
        }
        return "TSet<uint8>";
    }
    if (t == "mapproperty") {
        UEObject::Prop key, val;
        std::string k = "uint8";
        std::string v = "uint8";
        if (p.aux && sNest < kMaxNest && dummy.ReadPropertyAt(p.aux, key)) {
            sNest++;
            k = CppTypeFor(key);
            sNest--;
        }
        if (p.aux2 && sNest < kMaxNest && dummy.ReadPropertyAt(p.aux2, val)) {
            sNest++;
            v = CppTypeFor(val);
            sNest--;
        }
        return "TMap<" + k + ", " + v + ">";
    }
    if (t == "enumproperty" || t == "byteproperty") {
        return p.auxName.empty() ? "uint8" : "TEnumAsByte<" + CppEnumName(p.auxName) + ">";
    }
    if (t == "boolproperty")   return "bool";
    if (t == "floatproperty")  return "float";
    if (t == "doubleproperty") return "double";
    if (t == "intproperty")    return "int32_t";
    if (t == "int64property")  return "int64_t";
    if (t == "int16property")  return "int16_t";
    if (t == "int8property")   return "int8_t";
    if (t == "uint32property") return "uint32_t";
    if (t == "uint64property") return "uint64_t";
    if (t == "uint16property") return "uint16_t";
    if (t == "strproperty")    return "FString";
    if (t == "nameproperty")   return "FName";
    if (t == "textproperty")   return "FText";
    if (t == "delegateproperty") return "FScriptDelegate";
    if (t == "multicastdelegateproperty" ||
        t == "multicastinlinedelegateproperty" ||
        t == "multicastsparsedelegateproperty") {
        return "FMulticastScriptDelegate";
    }

    return "uint8"; // unknown - the caller adds an explanatory note comment
}

// ============================================================================
// name prefix heuristics
// ============================================================================

std::string SDKGenerator::CppClassName(const std::string& engineName) {
    if (engineName.empty()) return "";

    static const std::set<std::string> actorish = {
        "Actor", "Pawn", "Character", "Controller", "PlayerController", "AIController",
        "PlayerState", "GameStateBase", "GameState", "GameModeBase", "GameMode",
        "HUD", "Info", "ActorComponent", "SceneComponent", "PrimitiveComponent",
        "CameraActor", "World",
    };

    const char c0 = engineName[0];
    if (c0 == 'U' || c0 == 'A' || c0 == 'F' || c0 == 'E' || c0 == 'S' || c0 == 'I') {
        return str::SanitizeIdent(engineName);
    }

    const bool actor = str::EndsWith(engineName, "Component") || actorish.count(engineName) > 0;
    return str::SanitizeIdent(actor ? "A" + engineName : "U" + engineName);
}

std::string SDKGenerator::CppStructName(const std::string& engineName) {
    if (engineName.empty()) return "";
    return str::SanitizeIdent(engineName[0] == 'F' ? engineName : "F" + engineName);
}

std::string SDKGenerator::CppEnumName(const std::string& engineName) {
    if (engineName.empty()) return "";
    return str::SanitizeIdent(engineName[0] == 'E' ? engineName : "E" + engineName);
}

// ============================================================================
// CollectAncestorNames - union of all ancestors' property names
// ============================================================================

void SDKGenerator::CollectAncestorNames(const UEObject& cls, std::set<std::string>& out) {
    UEObject start = cls; // UEObject is a light handle (ctx/addr/index); methods are non-const
    u64 super = start.GetSuper();
    std::unordered_set<u64> visited;

    for (int hops = 0; super != 0 && hops < kMaxHops; hops++) {
        if (!visited.insert(super).second) break; // cycle guard

        UEObject node(&ctx_, super, -1);
        std::vector<UEObject::Prop> props = node.GetProperties();
        if (props.size() > kMaxProps) props.resize(kMaxProps);
        for (const UEObject::Prop& pr : props) {
            if (!pr.name.empty()) out.insert(pr.name);
        }
        super = node.GetSuper();
    }
}

} // namespace dumper
