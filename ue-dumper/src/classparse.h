// ============================================================================
//  UnrealDumperX - classparse.h
//  UClass / UScriptStruct / UEnum reflection parser feeding the SDK generator.
//
//  Handles BOTH reflection backends:
//    * UE4.25+ / UE5 : FField chain in UStruct::ChildProperties (+ UFunction
//      objects in Children)
//    * UE4.20-4.24   : legacy UProperty chain in UStruct::Children
//
//  UStruct/UFunction internal layouts vary across builds, so two layout
//  presets are probed and validated on live classes before use
//  (games.ini can pin them through [StructLayout]).
// ============================================================================
#pragma once
#include "ue_types.h"
#include "fname.h"
#include "finder.h"

namespace udx::ue {

struct PropertyInfo {
    std::string name;
    std::string type;        // C++ type text
    std::string comment;     // extra info (enum name, inner type...)
    int offset = 0;
    int size = 0;
    int arrayDim = 1;
    bool bitfield = false;
    bool outParam = false;
    bool returnParam = false;
    u64 propFlags = 0;
};

struct FunctionInfo {
    std::string name;
    std::string fullName;    // Function /Script/Engine.Actor.Foo
    u32 flags = 0;
    int numParams = 0;
    int parmsSize = 0;
    uintptr_t func = 0;
    std::string returnType;
    std::vector<PropertyInfo> params;
};

struct StructInfo {
    std::string name;
    std::string fullName;      // /Script/Engine.Actor
    std::string superName;
    std::string superPackage;
    std::string package;
    int size = 0;
    bool isClass = false;
    bool isStruct = false;
    std::vector<PropertyInfo> props;
    std::vector<FunctionInfo> funcs;
};

struct EnumInfo {
    std::string name;
    std::string package;
    std::string fullName;
    std::vector<std::pair<std::string, i32>> values;
};

class ClassParser {
public:
    // Internal layout description (public so the preset tables can live in
    // the .cpp file-scope).
    struct Layout {
        // UStruct
        int super, children, childProps, propsSize;
        // UObject size implied by the preset (0x30 for the 0x40 family).
        int uobjSize;
        // FField / FProperty (4.25+) - unused entries stay 0 for legacy.
        int fieldClass, fieldNext, fieldName, fieldFlags;
        int propArrayDim, propElementSize, propFlags, propOffset, propSize;
        int typedBase, boolByteMask, boolFieldMask;
        // UFunction
        int funcFlags, funcNumParams, funcParmsSize, funcRetValOff, funcFunc;
        bool useFFields;
    };
    ClassParser(Process& proc, Offsets& off, NameDb& names, ObjectDb& objects);

    std::optional<StructInfo> parseStruct(u64 classObjAddr, bool isClass);
    std::optional<EnumInfo> parseEnum(u64 enumObjAddr);

    std::string fullNameOf(u64 objAddr);    // "/Script/Engine.Actor"
    std::string packageOf(u64 objAddr);     // "Engine" (outermost object name)
    std::string classNameOf(u64 objAddr);   // FName of obj's ClassPrivate

    bool layoutChosen() const { return layout_ != nullptr; }
    const std::string& layoutNote() const { return layoutNote_; }

private:
    const Layout* pickLayout();
    bool validateLayout(const Layout& L);

    bool parsePropertiesFieldChain(u64 firstField, StructInfo& out);
    bool parseLegacyChildChain(u64 firstChild, StructInfo& out);
    bool parseFunction(u64 funcObj, FunctionInfo& out);
    PropertyInfo mapProperty(u64 fieldObj, const std::string& propClass,
                             const Layout& L, bool isParam);

    std::string typeNameFor(u64 propObj, const std::string& propClass,
                            const Layout& L, PropertyInfo& out, bool isParam);

    Process& proc_;
    Offsets& off_;
    NameDb& names_;
    ObjectDb& objects_;
    const Layout* layout_ = nullptr;
    std::string layoutNote_;
};

} // namespace udx::ue
