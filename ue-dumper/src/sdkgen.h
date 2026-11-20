// ============================================================================
//  UnrealDumperX - sdkgen.h
//  Module 1 - SDK generation (Dumper-7 / ill2cpp2dumper style output).
//
//  Output layout:
//    <outDir>/SDK/<Game>/Basic.h               minimal runtime + types
//    <outDir>/SDK/<Package>/<Package>_classes.h UObject-derived classes
//    <outDir>/SDK/<Package>/<Package>_struct.h  plain structs + enums
//
//  IMPORTANT NOTE #15 (SDK output details):
//    * gaps between members are emitted as  uint8 UnknownData_XX[0xYY];
//    * FBoolProperty members are emitted as bitfields  uint8 bName : 1;
//      with their byte mask preserved in the offset comment
//    * inheritance chains and cross-package includes are resolved
//    * UFunction members become ProcessEvent thunks (optional)
// ============================================================================
#pragma once
#include "classparse.h"

namespace udx::sdk {

struct SdkOptions {
    std::string outDir;       // dump output root
    std::string gameName;     // exe name without extension
    std::string version;      // "UE5.2" / "Unknown"
    bool eventThunks = true;  // emit ProcessEvent-based member functions
    int  processEventIndex = -1;  // discovered UObject vtable slot
};

class SdkGenerator {
public:
    SdkGenerator(Process& proc, ue::Offsets& off, ue::NameDb& names,
                 ue::ObjectDb& objects, ue::ClassParser& parser,
                 const SdkOptions& opts);

    // Walks every live object, parses classes/structs/enums, writes all files.
    // Returns false when nothing could be parsed.
    bool generate();

    const std::vector<std::string>& writtenFiles() const { return files_; }
    usize classCount() const { return classCount_; }
    usize structCount() const { return structCount_; }
    usize enumCount() const { return enumCount_; }
    usize packageCount() const { return packages_.size(); }

private:
    // package -> items
    std::map<std::string, std::vector<ue::StructInfo>> packages_;
    std::map<std::string, std::vector<ue::EnumInfo>> enumPackages_;
    std::map<std::string, std::string> packageOfName_;  // type name -> package
    std::vector<std::string> files_;
    usize classCount_ = 0, structCount_ = 0, enumCount_ = 0;

    Process& proc_;
    ue::Offsets& off_;
    ue::NameDb& names_;
    ue::ObjectDb& objects_;
    ue::ClassParser& parser_;
    SdkOptions opts_;

    void collect();
    void writeAll();
    std::string basicHeader() const;
    std::string emitClassesFile(const std::string& pkg) const;
    std::string emitStructsFile(const std::string& pkg) const;
    std::string emitMembers(const ue::StructInfo& s) const;
    std::string emitFunctions(const ue::StructInfo& s) const;
    static std::string memberName(const std::string& raw);
    static bool isCppKeyword(const std::string& id);
};

} // namespace udx::sdk
