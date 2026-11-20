// DumperPro - full C++ SDK generator (packages -> _classes.h / _structs.h / _enums.h)
#pragma once
#include "../framework.h"
#include "ue/UEObject.h"
#include "dump/VTableResolver.h"

namespace dumper {

class UEContext;

struct SDKOptions {
    fs::path outDir;
    bool genEnums = true;
    bool genStructs = true;
    bool genClasses = true;
    bool genFunctions = true;
    bool writeFuncsTxt = true;
    const std::map<std::string, VTResult>* vtResults = nullptr; // optional: name -> vtable result (tags funcs.txt)
};

class SDKGenerator {
public:
    SDKGenerator(UEContext& ctx, SDKOptions opt) : ctx_(ctx), opt_(std::move(opt)) {}

    bool Generate();   // writes SDK/... ; returns success

private:
    UEContext& ctx_;
    SDKOptions opt_;

    struct PackageInfo {
        std::string name;              // top-most outer name (package)
        std::vector<i32> objIndices;   // object indices belonging to this package
    };
    std::vector<PackageInfo> packages_;

    // --- passes ---
    void BuildPackages();
    void EmitBasics(const fs::path& sdkDir);
    void EmitMasterInclude(const fs::path& sdkDir);

    // --- per package ---
    bool GeneratePackage(const PackageInfo& pkg, size_t idx);
    void EmitEnums(std::ostream& os, const PackageInfo& pkg);
    void EmitStructsAndClasses(std::ostream& structsOs, std::ostream& classesOs, const PackageInfo& pkg);

    // --- helpers shared by emitters ---
    std::string CppTypeFor(const UEObject::Prop& p, bool forParam = false);
    std::string CppClassName(const std::string& engineName);      // "Actor" -> "AActor" heuristic
    std::string CppStructName(const std::string& engineName);     // ensure F prefix
    std::string CppEnumName(const std::string& engineName);       // ensure E prefix
    void EmitClassBody(std::ostream& os, const UEObject& cls);
    void EmitMembers(std::ostream& os, const UEObject& cls, u32 inheritedSize);
    void EmitFunctions(std::ostream& os, const UEObject& cls, std::vector<std::string>& funcsLines);
    void CollectAncestorNames(const UEObject& cls, std::set<std::string>& out);

    void WriteFuncsTxt(const fs::path& sdkDir, const std::vector<std::string>& lines);
};

} // namespace dumper
