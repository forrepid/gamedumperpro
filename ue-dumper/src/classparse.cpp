// ============================================================================
//  UnrealDumperX - classparse.cpp
// ============================================================================
#include "classparse.h"
#include "log.h"

namespace udx::ue {

ClassParser::ClassParser(Process& proc, Offsets& off, NameDb& names,
                         ObjectDb& objects)
    : proc_(proc), off_(off), names_(names), objects_(objects) {}

// ---------------------------------------------------------------------------
// Layout presets
// ---------------------------------------------------------------------------

namespace {

// Preset A: UE4.25-4.27 / UE5.0 (FField world, UObject size 0x30,
// UStruct::SuperStruct @0x40 family - Dumper-7 style offsets).
const ClassParser::Layout kLayoutA = {
    /*super*/ 0x40, /*children*/ 0x48, /*childProps*/ 0x50, /*propsSize*/ 0x58,
    /*uobjSize*/ 0x30,
    /*fieldClass*/ 0x08, /*fieldNext*/ 0x18, /*fieldName*/ 0x20, /*fieldFlags*/ 0x28,
    /*arrayDim*/ 0x30, /*elemSize*/ 0x34, /*propFlags*/ 0x38, /*offset*/ 0x40,
    /*size*/ 0x44, /*typedBase*/ 0x48, /*boolByte*/ 0x48, /*boolField*/ 0x4C,
    /*funcFlags*/ 0xB0, /*numParams*/ 0xB4, /*parmsSize*/ 0xB8,
    /*retValOff*/ 0xB6, /*func*/ 0xC0, /*useFFields*/ true,
};

// Preset B: UE5.1+ (same family; UFunction shifted slightly in some builds).
const ClassParser::Layout kLayoutB = {
    /*super*/ 0x40, /*children*/ 0x48, /*childProps*/ 0x50, /*propsSize*/ 0x58,
    /*uobjSize*/ 0x30,
    /*fieldClass*/ 0x08, /*fieldNext*/ 0x18, /*fieldName*/ 0x20, /*fieldFlags*/ 0x28,
    /*arrayDim*/ 0x30, /*elemSize*/ 0x34, /*propFlags*/ 0x38, /*offset*/ 0x40,
    /*size*/ 0x44, /*typedBase*/ 0x48, /*boolByte*/ 0x48, /*boolField*/ 0x4C,
    /*funcFlags*/ 0xB0, /*numParams*/ 0xB4, /*parmsSize*/ 0xB8,
    /*retValOff*/ 0xB6, /*func*/ 0xC0, /*useFFields*/ true,
};

// Preset C: UE4.20-4.24 legacy (UProperty chain, UObject size 0x28).
const ClassParser::Layout kLayoutC = {
    /*super*/ 0x30, /*children*/ 0x38, /*childProps*/ 0x00, /*propsSize*/ 0x40,
    /*uobjSize*/ 0x28,
    /*fieldClass*/ 0x00, /*fieldNext*/ 0x28, /*fieldName*/ 0x00, /*fieldFlags*/ 0x00,
    /*arrayDim*/ 0x30, /*elemSize*/ 0x34, /*propFlags*/ 0x38, /*offset*/ 0x44,
    /*size*/ 0x48, /*typedBase*/ 0x50, /*boolByte*/ 0x50, /*boolField*/ 0x54,
    /*funcFlags*/ 0x30, /*numParams*/ 0x34, /*parmsSize*/ 0x38,
    /*retValOff*/ 0x36, /*func*/ 0x40, /*useFFields*/ false,
};

const ClassParser::Layout kAllLayouts[] = {kLayoutA, kLayoutB, kLayoutC};

} // namespace

// ---------------------------------------------------------------------------
// Layout selection - validate on live classes (super chain + properties)
// ---------------------------------------------------------------------------
bool ClassParser::validateLayout(const Layout& L) {
    // Grab a few real UClass objects.
    const i32 num = objects_.count();
    usize validated = 0, tried = 0;
    for (i32 i = 0; i < num && validated < 3 && tried < 64; ++i) {
        const u64 obj = objects_.objectAt(i);
        if (!obj) continue;
        const u64 cls = proc_.read<u64>(obj + off_.uobjClass);
        if (!cls || !proc_.ptrReadable(cls)) continue;
        const u32 clsIdx = proc_.read<u32>(cls + off_.uobjName);
        const std::string cn = names_.get(clsIdx);
        if (cn != "Class" && cn != "ScriptStruct") continue;
        ++tried;

        // Super chain must terminate (<= 12 hops) with readable, named classes.
        u64 super = proc_.read<u64>(cls + L.super);
        bool chainOk = false;
        for (int hop = 0; hop < 12 && super; ++hop) {
            if (!proc_.ptrReadable(super)) break;
            const u32 nIdx = proc_.read<u32>(super + off_.uobjName);
            if (names_.get(nIdx).empty()) break;
            const u64 next = proc_.read<u64>(super + L.super);
            if (!next) { chainOk = true; break; }
            super = next;
        }
        if (!chainOk) continue;

        // Property walk must yield at least one named member for real classes.
        usize named = 0;
        u64 field = L.useFFields ? proc_.read<u64>(cls + L.childProps)
                                 : proc_.read<u64>(cls + L.children);
        for (int f = 0; field && f < 64; ++f) {
            const u64 nameAddr = L.useFFields ? (field + (u64)L.fieldName)
                                              : (field + (u64)off_.uobjName);
            if (!names_.get(proc_.read<u32>(nameAddr)).empty()) ++named;
            field = proc_.read<u64>(field + (u64)L.fieldNext);
        }
        if (named > 0 || L.useFFields) ++validated;
    }
    return validated >= 2 || (tried >= 1 && validated >= 1);
}

const ClassParser::Layout* ClassParser::pickLayout() {
    if (layout_) return layout_;

    // games.ini pin ([StructLayout] Preset = A|B|C).
    // (Read through a detached ini snapshot: the parser only gets Offsets,
    //  so presets are pinned through [Offsets] keys applied by applyIni.)
    for (const Layout& L : kAllLayouts) {
        if (validateLayout(L)) {
            layout_ = &L;
            layoutNote_ = L.useFFields
                              ? (L.func == 0xC0 ? "A (FField, UFunction@0xC0)"
                                                : "B (FField, alt UFunction)")
                              : "C (legacy UProperty)";
            log::ok("Struct layout: " + layoutNote_);
            return layout_;
        }
    }
    layout_ = &kLayoutA;
    layoutNote_ = "fallback A";
    log::warn("Struct layout dogrulanamadi - A preset kullanilacak");
    return layout_;
}

// ---------------------------------------------------------------------------
// Name helpers
// ---------------------------------------------------------------------------
std::string ClassParser::classNameOf(u64 objAddr) {
    if (!objAddr) return {};
    const u64 cls = proc_.read<u64>(objAddr + off_.uobjClass);
    if (!cls) return {};
    return names_.get(proc_.read<u32>(cls + off_.uobjName));
}

std::string ClassParser::fullNameOf(u64 objAddr) {
    std::vector<std::string> chain;
    u64 cur = objAddr;
    for (int i = 0; cur && i < 64; ++i) {
        chain.push_back(names_.get(proc_.read<u32>(cur + off_.uobjName)));
        cur = proc_.read<u64>(cur + off_.uobjOuter);
    }
    std::string out;
    for (usize i = chain.size(); i-- > 0;) {
        out += "/" + chain[i];
    }
    return out.empty() ? "/None" : out;
}

std::string ClassParser::packageOf(u64 objAddr) {
    u64 cur = objAddr, prev = 0;
    for (int i = 0; cur && i < 64; ++i) {
        prev = cur;
        cur = proc_.read<u64>(cur + off_.uobjOuter);
    }
    if (!prev) return {};
    return names_.get(proc_.read<u32>(prev + off_.uobjName));
}

// ---------------------------------------------------------------------------
// Property type mapping
// ---------------------------------------------------------------------------
std::string ClassParser::typeNameFor(u64 prop, const std::string& pc,
                                     const Layout& L, PropertyInfo& pi,
                                     bool isParam) {
    auto ptrAt = [&](int off) { return proc_.read<u64>(prop + (u64)off); };
    auto nameOfObj = [&](u64 o) {
        return o ? names_.get(proc_.read<u32>(o + off_.uobjName)) : std::string();
    };

    if (pc == "FloatProperty") return "float";
    if (pc == "DoubleProperty") return "double";
    if (pc == "IntProperty") return "int32";
    if (pc == "Int64Property") return "int64";
    if (pc == "Int16Property") return "int16";
    if (pc == "Int8Property") return "int8";
    if (pc == "UInt32Property") return "uint32";
    if (pc == "UInt64Property") return "uint64";
    if (pc == "UInt16Property") return "uint16";
    if (pc == "StrProperty") return "FString";
    if (pc == "NameProperty") return "FName";
    if (pc == "TextProperty") return "FText";

    if (pc == "ByteProperty") {
        const u64 e = ptrAt(L.typedBase);
        const std::string en = nameOfObj(e);
        if (!en.empty()) { pi.comment = "enum " + en; return sanitizeIdent(en); }
        return "uint8";
    }
    if (pc == "BoolProperty") {
        pi.bitfield = true;
        return "uint8";
    }
    if (pc == "ObjectProperty" || pc == "WeakObjectProperty" ||
        pc == "LazyObjectProperty" || pc == "SoftObjectProperty" ||
        pc == "ObjectPropertyBase") {
        const std::string cn = nameOfObj(ptrAt(L.typedBase));
        pi.comment = cn.empty() ? "class" : "class " + cn;
        return "UObject*";   // typed per-class pointers are resolved by users
    }
    if (pc == "ClassProperty") {
        const std::string cn = nameOfObj(ptrAt(L.typedBase));
        pi.comment = "meta " + (cn.empty() ? "class" : "class " + cn);
        return "UClass*";
    }
    if (pc == "StructProperty") {
        const std::string sn = nameOfObj(ptrAt(L.typedBase));
        if (!sn.empty()) { pi.comment = "struct " + sn; return sanitizeIdent(sn); }
        pi.comment = "struct ?";
        return "uint8";
    }
    if (pc == "EnumProperty") {
        const u64 e = ptrAt(L.typedBase);
        const std::string en = nameOfObj(e);
        if (!en.empty()) { pi.comment = "enum " + en; return sanitizeIdent(en); }
        return "uint8";
    }
    if (pc == "ArrayProperty") {
        const u64 inner = ptrAt(L.typedBase);
        const std::string innerCls = nameOfObj(inner ? proc_.read<u64>(inner) : 0);
        PropertyInfo dummy;
        const std::string innerType = inner
            ? typeNameFor(inner, nameOfObj(proc_.read<u64>(inner)), L, dummy, false)
            : "uint8";
        pi.comment = "TArray<" + innerType + ">";
        return "TArray<" + innerType + ">";
    }
    if (pc == "MapProperty") {
        const u64 key = ptrAt(L.typedBase);
        const u64 val = ptrAt(L.typedBase + 8);
        PropertyInfo dk, dv;
        const std::string kt = key ? typeNameFor(key, nameOfObj(proc_.read<u64>(key)), L, dk, false) : "uint8";
        const std::string vt = val ? typeNameFor(val, nameOfObj(proc_.read<u64>(val)), L, dv, false) : "uint8";
        pi.comment = "TMap<" + kt + ", " + vt + ">";
        return "TMap<" + kt + ", " + vt + ">";
    }
    if (pc == "SetProperty") {
        const u64 inner = ptrAt(L.typedBase);
        PropertyInfo d;
        const std::string it = inner ? typeNameFor(inner, nameOfObj(proc_.read<u64>(inner)), L, d, false) : "uint8";
        pi.comment = "TSet<" + it + ">";
        return "TSet<" + it + ">";
    }
    if (pc == "DelegateProperty") { pi.comment = "delegate"; return "FDelegate"; }
    if (pc == "MulticastDelegateProperty" || pc == "MulticastInlineDelegateProperty") {
        pi.comment = "multicast delegate";
        return "FMulticastDelegate";
    }
    if (pc == "InterfaceProperty") { pi.comment = "interface"; return "TScriptInterface<class UObject>"; }

    if (isParam) return "uint8";
    pi.comment = "property class " + pc;
    return "uint8";
}

ClassParser::PropertyInfo ClassParser::mapProperty(u64 prop,
                                                   const std::string& propClass,
                                                   const Layout& L,
                                                   bool isParam) {
    PropertyInfo pi;
    const u32 nameIdx = L.useFFields
        ? proc_.read<u32>(prop + (u64)L.fieldName)
        : proc_.read<u32>(prop + (u64)off_.uobjName);
    pi.name = names_.get(nameIdx);
    pi.offset = proc_.read<i32>(prop + (u64)L.propOffset);
    pi.size = proc_.read<i32>(prop + (u64)L.propElementSize);
    pi.arrayDim = proc_.read<i32>(prop + (u64)L.propArrayDim);
    if (pi.arrayDim <= 0) pi.arrayDim = 1;
    pi.propFlags = proc_.read<u64>(prop + (u64)L.propFlags);
    if (pi.propFlags > 0xFFFFFFFFULL) pi.propFlags &= 0xFFFFFFFFULL;
    pi.outParam = (pi.propFlags & 0x0000000000000100ULL) != 0;     // CPF_OutParm
    pi.returnParam = (pi.propFlags & 0x0000000000000400ULL) != 0;  // CPF_ReturnParm
    pi.type = typeNameFor(prop, propClass, L, pi, isParam);
    if (pi.bitfield) pi.size = 1;
    return pi;
}

// ---------------------------------------------------------------------------
// Property chains
// ---------------------------------------------------------------------------
bool ClassParser::parsePropertiesFieldChain(u64 firstField, StructInfo& out) {
    const Layout& L = *layout_;
    usize count = 0;
    for (u64 f = firstField; f && count < 4096; ++count) {
        const u64 fieldCls = proc_.read<u64>(f + (u64)L.fieldClass);
        const std::string pc = fieldCls
            ? names_.get(proc_.read<u32>(fieldCls + off_.uobjName))
            : std::string();
        if (pc.empty()) break;   // broken chain
        out.props.push_back(mapProperty(f, pc, L, false));
        f = proc_.read<u64>(f + (u64)L.fieldNext);
    }
    return count > 0;
}

bool ClassParser::parseLegacyChildChain(u64 firstChild, StructInfo& out) {
    const Layout& L = *layout_;
    usize count = 0;
    for (u64 f = firstChild; f && count < 4096; ++count) {
        const u64 fieldCls = proc_.read<u64>(f + off_.uobjClass);
        const std::string pc = fieldCls
            ? names_.get(proc_.read<u32>(fieldCls + off_.uobjName))
            : std::string();
        if (pc.empty()) break;
        if (endsWith(pc, "Property"))
            out.props.push_back(mapProperty(f, pc, L, false));
        else if (pc == "Function")
            parseFunction(f, out.funcs.emplace_back());
        f = proc_.read<u64>(f + (u64)L.fieldNext);   // UField::Next
    }
    return count > 0;
}

// ---------------------------------------------------------------------------
// UFunction
// ---------------------------------------------------------------------------
bool ClassParser::parseFunction(u64 funcObj, FunctionInfo& out) {
    const Layout& L = *layout_;
    const u32 nameIdx = proc_.read<u32>(funcObj + off_.uobjName);
    out.name = names_.get(nameIdx);
    if (out.name.empty()) return false;
    out.fullName = "Function " + fullNameOf(funcObj);
    out.flags = proc_.read<u32>(funcObj + (u64)L.funcFlags);
    out.numParams = proc_.read<u8>(funcObj + (u64)L.funcNumParams);
    out.parmsSize = proc_.read<u16>(funcObj + (u64)L.funcParmsSize);
    out.func = proc_.read<u64>(funcObj + (u64)L.funcFunc);

    // Parameters live in the function's own property chain.
    const u64 head = L.useFFields ? proc_.read<u64>(funcObj + (u64)L.childProps)
                                  : proc_.read<u64>(funcObj + (u64)L.children);
    usize count = 0;
    for (u64 f = head; f && count < 64; ++count) {
        std::string pc;
        if (L.useFFields) {
            const u64 cls = proc_.read<u64>(f + (u64)L.fieldClass);
            pc = cls ? names_.get(proc_.read<u32>(cls + off_.uobjName)) : std::string();
        } else {
            const u64 cls = proc_.read<u64>(f + off_.uobjClass);
            pc = cls ? names_.get(proc_.read<u32>(cls + off_.uobjName)) : std::string();
        }
        if (pc.empty()) break;
        if (endsWith(pc, "Property")) {
            PropertyInfo pi = mapProperty(f, pc, L, true);
            out.params.push_back(std::move(pi));
        }
        f = L.useFFields ? proc_.read<u64>(f + (u64)L.fieldNext)
                         : proc_.read<u64>(f + (u64)L.fieldNext);   // both use Next
    }
    std::sort(out.params.begin(), out.params.end(),
              [](const PropertyInfo& a, const PropertyInfo& b) {
                  return a.offset < b.offset;
              });
    for (const auto& p : out.params)
        if (p.returnParam) out.returnType = p.type;
    return true;
}

// ---------------------------------------------------------------------------
// Main struct parse
// ---------------------------------------------------------------------------
std::optional<StructInfo> ClassParser::parseStruct(u64 classObj, bool isClass) {
    const Layout& L = *pickLayout();

    StructInfo out;
    out.isClass = isClass;
    out.isStruct = !isClass;
    out.name = names_.get(proc_.read<u32>(classObj + off_.uobjName));
    if (out.name.empty()) return std::nullopt;
    out.fullName = fullNameOf(classObj);
    out.package = packageOf(classObj);
    if (out.package.empty()) out.package = out.name;

    // Super
    const u64 super = proc_.read<u64>(classObj + (u64)L.super);
    if (super) {
        out.superName = names_.get(proc_.read<u32>(super + off_.uobjName));
        out.superPackage = packageOf(super);
    }

    // Size
    const i32 propsSize = proc_.read<i32>(classObj + (u64)L.propsSize);
    out.size = propsSize > 0 && propsSize < (1 << 20)
        ? propsSize + L.uobjSize
        : L.uobjSize;

    // Members + functions
    if (L.useFFields) {
        parsePropertiesFieldChain(proc_.read<u64>(classObj + (u64)L.childProps), out);
        // UFunction objects live on the UField chain.
        usize count = 0;
        for (u64 f = proc_.read<u64>(classObj + (u64)L.children);
             f && count < 4096; ++count) {
            const u64 fieldCls = proc_.read<u64>(f + off_.uobjClass);
            const std::string pc = fieldCls
                ? names_.get(proc_.read<u32>(fieldCls + off_.uobjName))
                : std::string();
            if (pc.empty()) break;
            if (pc == "Function") parseFunction(f, out.funcs.emplace_back());
            f = proc_.read<u64>(f + (u64)L.fieldNext);
        }
    } else {
        parseLegacyChildChain(proc_.read<u64>(classObj + (u64)L.children), out);
    }

    std::sort(out.props.begin(), out.props.end(),
              [](const PropertyInfo& a, const PropertyInfo& b) {
                  return a.offset < b.offset;
              });

    // Sanity: members must live inside the declared size.
    usize ok = 0;
    for (const auto& p : out.props)
        if (p.offset >= 0 && p.offset < out.size + 0x1000) ++ok;
    if (out.props.size() >= 4 && ok * 2 < out.props.size()) return std::nullopt;
    return out;
}

// ---------------------------------------------------------------------------
// UEnum
// ---------------------------------------------------------------------------
std::optional<EnumInfo> ClassParser::parseEnum(u64 enumObj) {
    EnumInfo out;
    out.name = names_.get(proc_.read<u32>(enumObj + off_.uobjName));
    if (out.name.empty()) return std::nullopt;
    out.fullName = fullNameOf(enumObj);
    out.package = packageOf(enumObj);
    if (out.package.empty()) out.package = out.name;

    // Names TArray<TPair<FName, uint8>>: probe its offset + pair stride.
    for (int arrOff : {0x28, 0x30, 0x38}) {
        const u64 data = proc_.read<u64>(enumObj + (u64)arrOff);
        const i32 count = proc_.read<i32>(enumObj + (u64)arrOff + 8);
        if (!data || count <= 0 || count > 4096) continue;
        if (!proc_.ptrReadable(data)) continue;
        for (usize stride : {16, 12, 8}) {
            usize named = 0;
            for (i32 i = 0; i < count && i < 8; ++i) {
                const u32 idx = proc_.read<u32>(data + (u64)i * stride);
                if (!names_.get(idx).empty()) ++named;
            }
            if (named * 2 < std::min<i32>(count, 8)) continue;
            for (i32 i = 0; i < count; ++i) {
                const u64 item = data + (u64)i * stride;
                const std::string n = names_.get(proc_.read<u32>(item));
                const i32 v = proc_.read<u8>(item + 8);
                if (!n.empty()) out.values.emplace_back(n, v);
            }
            return out;
        }
    }
    return std::nullopt;
}

} // namespace udx::ue
