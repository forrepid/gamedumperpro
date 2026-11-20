// ============================================================================
// DumperPro - UEObject.cpp
// UEContext / UEObject: offset-driven, high-level reads over UObject memory.
//
// Engine-semantics notes:
//  * Every structure offset comes from ctx->off (profile / runtime probe);
//    nothing is hardcoded. An offset of 0 always means "unknown / not
//    present" and leaves the corresponding value defaulted.
//  * All memory access goes through UEContext::reader (IMemoryReader), which
//    is bounds-safe by design: Read() returns false on failure and every
//    caller falls back to a zero/empty default.
//  * Every linked-list walk (Children / ChildProperties / Outer / UEnum
//    names) is iteration-capped so corrupt or cyclic data can never spin.
// ============================================================================

#include "ue/UEObject.h"
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"
#include "core/MemoryReader.h"
#include "utils/StrUtil.h"
#include "utils/Logger.h"

namespace dumper {

namespace {

// hard caps so cyclic / corrupt chains can never loop forever
constexpr u32 kMaxChainIter   = 20000;
constexpr i32 kMaxEnumEntries = 65536;
constexpr int kMaxOuterHops   = 64;

// common guard for UEObject methods: context, reader and address must be live
inline bool ObjReady(const UEObject& o) { return o.ctx && o.ctx->reader && o.addr != 0; }

} // namespace

// ---------------------------------------------------------------------------
// UEContext - FName / field-class plumbing
// ---------------------------------------------------------------------------

FNameValue UEContext::ReadFName(u64 a) const {
    if (!reader || !a) return FNameValue{-1, 0};
    i32 idx = 0, num = 0;
    if (!reader->ReadI32(a, idx) || !reader->ReadI32(a + 4, num)) return FNameValue{-1, 0};
    if (idx < 0) return FNameValue{-1, 0}; // a FName index is never negative
    return FNameValue{idx, num};
}

std::string UEContext::NameString(const FNameValue& f, bool withNumber) const {
    if (!names || f.index < 0) return "";
    std::string s = names->Get(f.index); // "" when the index is invalid
    if (s.empty()) return "";
    // duplicate FNames store Number = occurrence + 1 ("Foo" -> "Foo_2")
    if (withNumber && f.number > 0) s += "_" + std::to_string(f.number - 1);
    return s;
}

std::string UEContext::NameAt(u64 a) const {
    return NameString(ReadFName(a));
}

std::string UEContext::FieldClassName(u64 fieldAddr) const {
    if (!reader || !IsValidHeapPtr(fieldAddr)) return "";
    const UEOffsets& o = off;

    if (o.useFFields) {
        // FField model (UE4.25+ / UE5): ClassPrivate is an FFieldClass* whose
        // Name is a plain FName ("ObjectProperty", "BoolProperty", ...).
        if (o.ffClassOff && o.ffClassNameOff) {
            u64 ffc = 0;
            if (reader->ReadPtr(fieldAddr + o.ffClassOff, ffc) && IsValidHeapPtr(ffc)) {
                const std::string n = NameAt(ffc + o.ffClassNameOff);
                if (!n.empty()) return n;
            }
        }
        // fall through: entries of a UStruct::Children chain are UObject based
        // (UFunction & co) even in FField mode, so their class name must be
        // resolved through the regular UClass pointer below. For genuine
        // FFields the FFieldClass path above always resolves and this is
        // never reached.
    }

    // UObject model (or UObject-based field): ClassPrivate -> class FName
    if (o.objClassOff && o.objNameOff) {
        u64 cls = 0;
        if (reader->ReadPtr(fieldAddr + o.objClassOff, cls) && IsValidHeapPtr(cls))
            return NameAt(cls + o.objNameOff);
    }
    return "";
}

bool UEContext::IsValidHeapPtr(u64 p) const {
    return p != 0 && (p & 7) == 0 && p > 0x1000 && p < 0x7FFFFFFEFFFFull;
}

// ---------------------------------------------------------------------------
// UEObject - raw field readers (0 on any failure)
// ---------------------------------------------------------------------------

u32 UEObject::GetFlags() {
    if (!ObjReady(*this) || !ctx->off.objFlagsOff) return 0;
    return ctx->reader->ReadU32Or(addr + ctx->off.objFlagsOff, 0);
}

u64 UEObject::GetClass() {
    if (!ObjReady(*this) || !ctx->off.objClassOff) return 0;
    u64 p = 0;
    ctx->reader->ReadPtr(addr + ctx->off.objClassOff, p);
    return p;
}

u64 UEObject::GetOuter() {
    if (!ObjReady(*this) || !ctx->off.objOuterOff) return 0;
    u64 p = 0;
    ctx->reader->ReadPtr(addr + ctx->off.objOuterOff, p);
    return p;
}

u64 UEObject::GetSuper() {
    if (!ObjReady(*this) || !ctx->off.stSuperOff) return 0;
    u64 p = 0;
    ctx->reader->ReadPtr(addr + ctx->off.stSuperOff, p);
    return p;
}

u64 UEObject::GetChildren() {
    if (!ObjReady(*this) || !ctx->off.stChildrenOff) return 0;
    u64 p = 0;
    ctx->reader->ReadPtr(addr + ctx->off.stChildrenOff, p);
    return p;
}

u64 UEObject::GetChildProperties() {
    // stChildPropsOff == 0 => pre-4.25 layout, no ChildProperties chain
    if (!ObjReady(*this) || !ctx->off.stChildPropsOff) return 0;
    u64 p = 0;
    ctx->reader->ReadPtr(addr + ctx->off.stChildPropsOff, p);
    return p;
}

u32 UEObject::GetPropertiesSize() {
    if (!ObjReady(*this) || !ctx->off.stPropsSizeOff) return 0;
    return ctx->reader->ReadU32Or(addr + ctx->off.stPropsSizeOff, 0);
}

u64 UEObject::GetCDO() {
    // clsCDOOff == 0 => offset unknown, report 0
    if (!ObjReady(*this) || !ctx->off.clsCDOOff) return 0;
    u64 p = 0;
    ctx->reader->ReadPtr(addr + ctx->off.clsCDOOff, p);
    return p;
}

// ---------------------------------------------------------------------------
// UEObject - names / classification
// ---------------------------------------------------------------------------

std::string UEObject::GetName() {
    if (!ObjReady(*this) || !ctx->off.objNameOff) return "";
    return ctx->NameAt(addr + ctx->off.objNameOff);
}

std::string UEObject::GetClassName() {
    if (!ObjReady(*this) || !ctx->off.objClassOff || !ctx->off.objNameOff) return "";
    const u64 cls = ctx->reader->ReadPtrOr(addr + ctx->off.objClassOff, 0);
    if (!ctx->IsValidHeapPtr(cls)) return "";
    return ctx->NameAt(cls + ctx->off.objNameOff);
}

std::string UEObject::GetTypeName() {
    return GetClassName();
}

std::string UEObject::GetPathName() {
    if (!ObjReady(*this)) return "";

    // Collect names from the leaf up, then join reversed with '/'.
    // The outer-most object is a UPackage whose FName already carries the
    // leading '/' ("/Script", "/Game/..."), so the joined result reads
    // "/Script/Engine/Object" as expected.
    std::vector<std::string> parts;
    parts.push_back(GetName());

    u64 cur = GetOuter();
    for (int hops = 0; cur != 0 && hops < kMaxOuterHops; ++hops) { // hop cap guards cycles
        UEObject o(ctx, cur, -1);
        std::string n = o.GetName();
        if (n.empty()) break; // unreadable outer -> keep the partial path
        parts.push_back(std::move(n));
        cur = o.GetOuter();
    }

    std::string path;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!path.empty()) path += '/';
        path += *it;
    }
    return path;
}

bool UEObject::IsType(const char* className) {
    if (!className) return false;
    return str::Lower(GetClassName()) == str::Lower(className);
}

bool UEObject::IsClassObj()    { return IsType("Class"); }
bool UEObject::IsStructObj()   { return IsType("ScriptStruct"); }
bool UEObject::IsEnumObj()     { return IsType("Enum"); }
bool UEObject::IsFunctionObj() { return IsType("Function"); }

// ---------------------------------------------------------------------------
// UEObject - properties / functions / enums
// ---------------------------------------------------------------------------

std::vector<UEObject::Prop> UEObject::GetProperties() {
    std::vector<Prop> out;
    if (!ObjReady(*this)) return out;
    const UEOffsets& off = ctx->off;

    u64 cur = 0;
    if (off.useFFields) {
        // FField model (UE4.25+ / UE5): FProperty objects form a linked list
        // at ChildProperties, chained through FField::Next. Functions never
        // live here; the "Function" filter is kept as a cheap guard against
        // bogus chains.
        cur = GetChildProperties();
        for (u32 it = 0; cur && it < kMaxChainIter; ++it) {
            if (ctx->FieldClassName(cur) != "Function") {
                Prop p;
                if (ReadPropertyAt(cur, p)) out.push_back(std::move(p));
            }
            cur = off.ffNextOff ? ctx->reader->ReadPtrOr(cur + off.ffNextOff, 0) : 0;
        }
    } else {
        // UProperty model (UE4 <= 4.24): properties sit in the UField Children
        // chain, chained through UField::Next. Their type name is the UClass
        // name of the property object ("ObjectProperty", ...).
        cur = GetChildren();
        for (u32 it = 0; cur && it < kMaxChainIter; ++it) {
            const std::string type = ctx->FieldClassName(cur);
            if (!type.empty() && type != "Function") {
                Prop p;
                if (ReadPropertyAt(cur, p)) out.push_back(std::move(p));
            }
            cur = off.fieldNextOff ? ctx->reader->ReadPtrOr(cur + off.fieldNextOff, 0) : 0;
        }
    }

    if (cur) // loop left a live pointer -> the iteration cap saved us
        Log::Debug("GetProperties: chain walk hit %u-iteration cap at %s (corrupt chain?)",
                   kMaxChainIter, Hex(cur).c_str());
    return out;
}

std::vector<UEObject::Func> UEObject::GetFunctions() {
    std::vector<Func> out;
    if (!ObjReady(*this)) return out;
    const UEOffsets& off = ctx->off;

    // UFunctions are UField based and therefore hang off the Children chain
    // in BOTH property models; only their parameter list location differs.
    u64 cur = GetChildren();
    for (u32 it = 0; cur && it < kMaxChainIter; ++it) {
        if (ctx->FieldClassName(cur) == "Function") {
            Func f;
            f.addr = cur;
            if (off.objNameOff)      f.name       = ctx->NameAt(cur + off.objNameOff);
            if (off.fnParamsSizeOff) f.paramsSize = ctx->reader->ReadU32Or(cur + off.fnParamsSizeOff, 0);
            if (off.fnFlagsOff)      f.flags      = ctx->reader->ReadU32Or(cur + off.fnFlagsOff, 0);
            // native exec pointer; 0 when the function is scripted (or the
            // offset is unknown / the read failed)
            if (off.fnFuncOff)       f.nativeFunc = ctx->reader->ReadPtrOr(cur + off.fnFuncOff, 0);

            // Parameter list:
            //   FField model    -> FProperty chain at ChildProperties (FField::Next)
            //   UProperty model -> UProperty chain at Children (UField::Next)
            u64 pcur = 0;
            u32 pnext = 0;
            if (off.useFFields) {
                pnext = off.ffNextOff;
                if (off.stChildPropsOff) pcur = ctx->reader->ReadPtrOr(cur + off.stChildPropsOff, 0);
            } else {
                pnext = off.fieldNextOff;
                if (off.stChildrenOff) pcur = ctx->reader->ReadPtrOr(cur + off.stChildrenOff, 0);
            }
            for (u32 pit = 0; pcur && pit < kMaxChainIter; ++pit) {
                Prop p;
                if (ReadPropertyAt(pcur, p)) {
                    // CPF_ReturnParm marks the return value; CPF_OutParm
                    // params stay in params with their flags kept so the SDK
                    // generator can comment them.
                    if (p.flags & UEOffsets::CPF_ReturnParm) f.ret = std::move(p);
                    else                                     f.params.push_back(std::move(p));
                }
                pcur = pnext ? ctx->reader->ReadPtrOr(pcur + pnext, 0) : 0;
            }
            if (pcur)
                Log::Debug("GetFunctions: parameter chain hit %u-iteration cap at %s (corrupt chain?)",
                           kMaxChainIter, Hex(pcur).c_str());

            out.push_back(std::move(f));
        }
        cur = off.fieldNextOff ? ctx->reader->ReadPtrOr(cur + off.fieldNextOff, 0) : 0;
    }

    if (cur)
        Log::Debug("GetFunctions: children walk hit %u-iteration cap at %s (corrupt chain?)",
                   kMaxChainIter, Hex(cur).c_str());
    return out;
}

std::vector<std::pair<std::string, int>> UEObject::GetEnumValues() {
    std::vector<std::pair<std::string, int>> out;
    if (!ObjReady(*this) || !ctx->off.enumNamesOff || !ctx->names) return out;
    const UEOffsets& off = ctx->off;

    // UEnum::Names is TArray<TPair<FName, uint8>>: { void* Data; i32 Num }
    u64 data = 0;
    i32 num = 0;
    if (!ctx->reader->ReadPtr(addr + off.enumNamesOff, data)) return out;
    if (!ctx->reader->ReadI32(addr + off.enumNamesOff + 8, num)) return out;
    if (num <= 0 || num > kMaxEnumEntries) return out; // corrupt count -> refuse
    if (!ctx->IsValidHeapPtr(data)) return out;

    const i32 nameCount = ctx->names->Num();

    // The pair is either 12 bytes (default layout: {i32,i32,u8} + padding) or
    // 9 bytes (packed); in both cases NameNumber sits at +4 and Value at +8.
    // Pick the stride for which every entry yields a valid FName index.
    auto strideValid = [&](u32 stride) -> bool {
        for (i32 i = 0; i < num; ++i) {
            i32 idx = 0;
            if (!ctx->reader->ReadI32(data + (u64)i * stride, idx)) return false;
            if (idx < 0 || idx >= nameCount) return false;
        }
        return true;
    };
    u32 stride = 0;
    if (strideValid(12)) stride = 12;
    else if (strideValid(9)) stride = 9;
    if (!stride) return out; // neither layout validates -> refuse to guess

    for (i32 i = 0; i < num; ++i) {
        const u64 e = data + (u64)i * stride;
        i32 nIdx = 0, nNum = 0;
        u8 value = 0;
        if (!ctx->reader->ReadI32(e, nIdx) ||
            !ctx->reader->ReadI32(e + 4, nNum) ||
            !ctx->reader->ReadU8(e + 8, value))
            break;
        std::string n = ctx->NameString(FNameValue{nIdx, nNum});
        if (n.empty()) break; // stop early when the name index is invalid
        out.emplace_back(std::move(n), (int)value);
    }
    return out;
}

bool UEObject::ReadPropertyAt(u64 fieldAddr, Prop& out) {
    out = Prop{}; // reset to header defaults (arrayDim 1, offset -1, ...)
    if (!ctx || !ctx->reader) return false;
    if (!ctx->IsValidHeapPtr(fieldAddr)) return false;
    const UEOffsets& off = ctx->off;

    out.addr = fieldAddr;

    // Base identity: FName + type name. The FField model reads the FName at
    // FField::NamePrivate; the UProperty model at UObject::NamePrivate.
    const u32 nameOff = off.useFFields ? off.ffNameOff : off.objNameOff;
    if (!nameOff) return false;
    const FNameValue fn = ctx->ReadFName(fieldAddr + nameOff);
    out.name = ctx->NameString(fn);
    out.type = ctx->FieldClassName(fieldAddr);
    // base reads failed (or type unknown) -> report failure, keep partial Prop
    if (fn.index < 0 || out.name.empty() || out.type.empty()) return false;

    // numeric basics (a failed read keeps the default)
    if (off.propArrayDimOff) {
        out.arrayDim = ctx->reader->ReadI32Or(fieldAddr + off.propArrayDimOff, 0);
        if (out.arrayDim == 0) out.arrayDim = 1; // 0 => scalar
    }
    if (off.propElementSizeOff) out.elementSize = ctx->reader->ReadI32Or(fieldAddr + off.propElementSizeOff, 0);
    if (off.propOffsetOff)      out.offset      = ctx->reader->ReadI32Or(fieldAddr + off.propOffsetOff, -1);
    if (off.propFlagsOff)       out.flags       = ctx->reader->ReadU64Or(fieldAddr + off.propFlagsOff, 0);

    // ---- typed extras ------------------------------------------------------
    // All extra offsets may be 0 (= unknown / not probed) -> leave aux at 0.
    const std::string& t = out.type;

    // guarded pointer field at fieldAddr + o (0 when unknown / unreadable)
    auto auxPtrAt = [&](u32 o) -> u64 {
        if (!o) return 0;
        u64 p = 0;
        if (!ctx->reader->ReadPtr(fieldAddr + o, p)) return 0;
        return ctx->IsValidHeapPtr(p) ? p : 0;
    };
    // FName of a UObject-based target ("" when unavailable)
    auto objNameAt = [&](u64 objAddr) -> std::string {
        if (!objAddr || !off.objNameOff) return "";
        return ctx->NameAt(objAddr + off.objNameOff);
    };

    if (str::Contains(t, "ObjectProperty")) {
        // ObjectProperty / WeakObjectProperty / SoftObjectProperty /
        // LazyObjectProperty: PropertyClass points at a UClass object
        out.aux = auxPtrAt(off.objPropClassOff);
        out.auxName = objNameAt(out.aux);
    } else if (t == "ClassProperty") {
        out.aux = auxPtrAt(off.objPropClassOff);   // also a UClass object
        out.auxName = objNameAt(out.aux);
    } else if (t == "StructProperty") {
        out.aux = auxPtrAt(off.structPropOff);     // UScriptStruct object
        out.auxName = objNameAt(out.aux);
    } else if (t == "ArrayProperty") {
        out.aux = auxPtrAt(off.arrayPropInnerOff); // inner property address, deliberately unresolved
    } else if (t == "SetProperty") {
        out.aux = auxPtrAt(off.setPropInnerOff);
    } else if (t == "MapProperty") {
        out.aux  = auxPtrAt(off.mapPropKeyOff);    // key property
        out.aux2 = auxPtrAt(off.mapPropValueOff);  // value property
    } else if (t == "EnumProperty" || t == "ByteProperty") {
        // 0 is legal for a plain uint8 ByteProperty (no enumerator attached)
        const u64 enumPtr = auxPtrAt(off.enumPropEnumOff);
        if (enumPtr) {
            UEObject e(ctx, enumPtr, -1);
            if (e.IsEnumObj()) {                   // accept genuine UEnum targets only
                out.aux = enumPtr;
                out.auxName = e.GetName();
            }
        }
    } else if (t == "BoolProperty") {
        if (off.boolByteMaskOff)  out.byteMask  = ctx->reader->ReadI32Or(fieldAddr + off.boolByteMaskOff, 0);
        if (off.boolFieldMaskOff) out.fieldMask = ctx->reader->ReadI32Or(fieldAddr + off.boolFieldMaskOff, 0);
    }

    return true;
}

} // namespace dumper
