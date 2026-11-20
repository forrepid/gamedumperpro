// DumperPro - engine structure offsets (profile-driven + runtime probing)
#pragma once
#include "../framework.h"
#include "ue/UEVersion.h"

namespace dumper {

struct UEOffsets {
    // ---- global addresses (filled by SigFinder / games.ini) ----
    u64 GObjectsVA = 0;
    u64 GNamesVA = 0;

    // ---- FUObjectArray internals (offsets within the FUObjectArray global) ----
    u32 oaChunksPtrOff = 0x10;   // FChunkedFixedUObjectArray::Objects (chunk pointer table)
    u32 oaMaxElemsOff  = 0x18;
    u32 oaNumElemsOff  = 0x1C;
    u32 oaMaxChunksOff = 0x20;
    u32 oaNumChunksOff = 0x24;
    bool oaFlat = false;         // true => FFixedUObjectArray (flat item array, no chunks)
    u32 oaItemStride = 0;        // 0 = auto (0x10 / 0x18 / 0x20)
    u32 oaChunkSize  = 0;        // 0 = auto (10240 UE4 / 65536 UE5)

    // ---- UObject ----
    u32 objFlagsOff = 0x08;
    u32 objIndexOff = 0x0C;      // InternalIndex (0 => probe)
    u32 objClassOff = 0x10;
    u32 objNameOff  = 0x18;      // NamePrivate (FName: i32 index, i32 number)
    u32 objOuterOff = 0x20;

    // ---- UField (UObject-based chain, used for functions & pre-4.25 properties) ----
    u32 fieldNextOff = 0x28;

    // ---- FField model (UE 4.25+ / UE5) ----
    bool useFFields = true;
    u32 ffClassOff      = 0x08;  // FField::ClassPrivate (FFieldClass*)
    u32 ffOwnerOff      = 0x10;
    u32 ffNextOff       = 0x18;
    u32 ffNameOff       = 0x20;
    u32 ffFlagsOff      = 0x28;
    u32 ffClassNameOff  = 0x08;  // FFieldClass::Name (FName)

    // ---- FProperty / UProperty common ----
    u32 propArrayDimOff    = 0x30;
    u32 propElementSizeOff = 0x34;
    u32 propFlagsOff       = 0x38; // u64 EPropertyFlags
    u32 propOffsetOff      = 0x4C; // Offset_Internal
    // typed extras: 0 => probe
    u32 objPropClassOff   = 0;   // FObjectPropertyBase::PropertyClass / UObjectProperty::PropertyClass
    u32 structPropOff     = 0;   // FStructProperty::Struct
    u32 arrayPropInnerOff = 0;   // FArrayProperty::Inner
    u32 setPropInnerOff   = 0;   // FSetProperty::Inner
    u32 mapPropKeyOff     = 0;   // FMapProperty::KeyProperty
    u32 mapPropValueOff   = 0;   // FMapProperty::ValueProperty
    u32 enumPropEnumOff   = 0;   // FEnumProperty::Enum / FByteProperty::Enum
    u32 boolByteMaskOff   = 0;   // FBoolProperty::ByteMask
    u32 boolFieldMaskOff  = 0;   // FBoolProperty::FieldMask

    // ---- UStruct ----
    u32 stSuperOff      = 0x30;
    u32 stChildrenOff   = 0x38;
    u32 stChildPropsOff = 0x40;  // 0 when not present (pre-4.25)
    u32 stPropsSizeOff  = 0x48;  // 0x40 pre-4.25

    // ---- UClass ----
    u32 clsCDOOff = 0;           // 0 => probe (ClassDefaultObject)

    // ---- UEnum ----
    u32 enumNamesOff = 0x30;     // TArray<TPair<FName, uint8>>

    // ---- UFunction ----
    u32 fnParamsSizeOff = 0x30;
    u32 fnFlagsOff      = 0x3C;
    u32 fnFuncOff       = 0;     // native exec pointer; 0 => probe

    // ---- provenance / confidence (filled by OffsetProbe) ----
    enum class Src { Missing, Profile, AutoDetect };
    struct Prov { Src src = Src::Missing; int confidence = 0; };
    std::unordered_map<std::string, Prov> prov;

    // dotted.key -> member binding (games.ini / probing / offsets.txt)
    u32* Bind(const std::string& key);
    bool* BindBool(const std::string& key);
    std::map<std::string, u32*> BindAllU32();
    std::map<std::string, bool*> BindAllBool();

    // version-dependent defaults (UE5 defaults are the declared ones)
    void SetDefaultsFor(const UEVersion& v);

    // known EPropertyFlags bits (for validation)
    static constexpr u64 kPropertyFlagMask = 0x003FFFFFull;
    // EObjectFlags RF_ClassDefaultObject
    static constexpr u32 kCDOFlag = 0x01000000;
    // EFunctionFlags FUNC_Native
    static constexpr u32 kFuncNative = 0x400;
    // EPropertyFlags
    static constexpr u64 CPF_Parm       = 0x0000000000000080ull;
    static constexpr u64 CPF_OutParm    = 0x0000000000000100ull;
    static constexpr u64 CPF_ReturnParm = 0x0000000000000200ull;
    static constexpr u64 CPF_ConstParm  = 0x0000000000000002ull;
};

} // namespace dumper
