// DumperPro - object wrapper: high level reads over UObject memory
#pragma once
#include "../framework.h"
#include "ue/Offsets.h"

namespace dumper {

class ObjectArray;
class NameArray;
class IMemoryReader;
class ModuleImage;

struct FNameValue {
    i32 index = -1;
    i32 number = 0;
};

// global engine context shared by all dumpers
class UEContext {
public:
    IMemoryReader* reader = nullptr;
    ModuleImage*   mod = nullptr;
    UEOffsets      off;
    UEVersion      ver;
    ObjectArray*   objects = nullptr;
    NameArray*     names = nullptr;

    FNameValue ReadFName(u64 addr) const;                  // reads {i32,i32}
    std::string NameString(const FNameValue& f, bool withNumber = true) const;
    std::string NameAt(u64 addr) const;                    // FName at addr -> string
    std::string FieldClassName(u64 fieldAddr) const;       // FFieldClass::Name or UClass name
    bool IsValidHeapPtr(u64 p) const;                      // quick sanity (nonzero, aligned, range)
};

class UEObject {
public:
    UEContext* ctx = nullptr;
    u64 addr = 0;
    i32 index = -1;

    UEObject() = default;
    UEObject(UEContext* c, u64 a, i32 idx) : ctx(c), addr(a), index(idx) {}
    bool IsValid() const { return ctx != nullptr && addr != 0; }

    u32 GetFlags();
    u64 GetClass();
    u64 GetOuter();
    u64 GetSuper();
    u64 GetChildren();
    u64 GetChildProperties();
    u32 GetPropertiesSize();
    u64 GetCDO();

    std::string GetName();       // FName (with number suffix when > 0)
    std::string GetClassName();  // class object's name
    std::string GetTypeName();   // alias of GetClassName
    std::string GetPathName();   // "/Outer/Outer/Name" (bounded depth)

    bool IsType(const char* className);   // GetClassName() == className (ci)
    bool IsClassObj();                    // class name == "Class"
    bool IsStructObj();                   // class name == "ScriptStruct"
    bool IsEnumObj();                     // class name == "Enum"
    bool IsFunctionObj();                 // class name == "Function"

    struct Prop {
        u64 addr = 0;
        std::string name;       // property name
        std::string type;       // "ObjectProperty", "StructProperty", ...
        i32 arrayDim = 1;
        i32 elementSize = 0;
        i32 offset = -1;        // Offset_Internal
        u64 flags = 0;          // EPropertyFlags
        i32 byteMask = 0;       // BoolProperty
        i32 fieldMask = 0;      // BoolProperty
        u64 aux = 0;            // PropertyClass / Struct / Inner / Enum / MapKey target addr
        u64 aux2 = 0;           // MapValue target addr
        std::string auxName;    // resolved name of aux target (class/struct/enum name)
        std::string aux2Name;   // resolved name of aux2 target
    };

    struct Func {
        u64 addr = 0;           // UFunction object address (VA)
        std::string name;
        u32 paramsSize = 0;
        u64 flags = 0;
        u64 nativeFunc = 0;     // UFunction::Func (native exec pointer)
        std::vector<Prop> params;
        std::optional<Prop> ret;
    };

    std::vector<Prop> GetProperties();   // fields only (excludes functions)
    std::vector<Func> GetFunctions();
    std::vector<std::pair<std::string, int>> GetEnumValues();

    // read a single property object at an explicit address (for Inner / Map parts)
    bool ReadPropertyAt(u64 fieldAddr, Prop& out);
};

} // namespace dumper
