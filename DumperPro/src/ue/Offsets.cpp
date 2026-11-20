#include "ue/Offsets.h"

namespace dumper {

u32* UEOffsets::Bind(const std::string& key) {
    if (key == "array.chunks_ptr")   return &oaChunksPtrOff;
    if (key == "array.max_elements") return &oaMaxElemsOff;
    if (key == "array.num_elements") return &oaNumElemsOff;
    if (key == "array.max_chunks")   return &oaMaxChunksOff;
    if (key == "array.num_chunks")   return &oaNumChunksOff;
    if (key == "array.item_stride")  return &oaItemStride;
    if (key == "array.chunk_size")   return &oaChunkSize;

    if (key == "uobject.flags") return &objFlagsOff;
    if (key == "uobject.index") return &objIndexOff;
    if (key == "uobject.class") return &objClassOff;
    if (key == "uobject.name")  return &objNameOff;
    if (key == "uobject.outer") return &objOuterOff;

    if (key == "ufield.next") return &fieldNextOff;

    if (key == "ffield.class")      return &ffClassOff;
    if (key == "ffield.owner")      return &ffOwnerOff;
    if (key == "ffield.next")       return &ffNextOff;
    if (key == "ffield.name")       return &ffNameOff;
    if (key == "ffield.flags")      return &ffFlagsOff;
    if (key == "ffield.class_name") return &ffClassNameOff;

    if (key == "property.arraydim")     return &propArrayDimOff;
    if (key == "property.elementsize")  return &propElementSizeOff;
    if (key == "property.flags")        return &propFlagsOff;
    if (key == "property.offset")       return &propOffsetOff;
    if (key == "property.objectclass")  return &objPropClassOff;
    if (key == "property.struct")       return &structPropOff;
    if (key == "property.array_inner")  return &arrayPropInnerOff;
    if (key == "property.set_inner")    return &setPropInnerOff;
    if (key == "property.map_key")      return &mapPropKeyOff;
    if (key == "property.map_value")    return &mapPropValueOff;
    if (key == "property.enum")         return &enumPropEnumOff;
    if (key == "property.bool_bytemask")   return &boolByteMaskOff;
    if (key == "property.bool_fieldmask")  return &boolFieldMaskOff;

    if (key == "struct.super")          return &stSuperOff;
    if (key == "struct.children")       return &stChildrenOff;
    if (key == "struct.childproperties") return &stChildPropsOff;
    if (key == "struct.propertiessize") return &stPropsSizeOff;

    if (key == "class.cdo")    return &clsCDOOff;
    if (key == "enum.names")   return &enumNamesOff;

    if (key == "function.paramssize") return &fnParamsSizeOff;
    if (key == "function.flags")      return &fnFlagsOff;
    if (key == "function.func")       return &fnFuncOff;

    return nullptr;
}

bool* UEOffsets::BindBool(const std::string& key) {
    if (key == "array.flat")        return &oaFlat;
    if (key == "ffield.enabled")    return &useFFields;
    return nullptr;
}

std::map<std::string, u32*> UEOffsets::BindAllU32() {
    static const char* keys[] = {
        "array.chunks_ptr", "array.max_elements", "array.num_elements", "array.max_chunks",
        "array.num_chunks", "array.item_stride", "array.chunk_size",
        "uobject.flags", "uobject.index", "uobject.class", "uobject.name", "uobject.outer",
        "ufield.next",
        "ffield.class", "ffield.owner", "ffield.next", "ffield.name", "ffield.flags", "ffield.class_name",
        "property.arraydim", "property.elementsize", "property.flags", "property.offset",
        "property.objectclass", "property.struct", "property.array_inner", "property.set_inner",
        "property.map_key", "property.map_value", "property.enum",
        "property.bool_bytemask", "property.bool_fieldmask",
        "struct.super", "struct.children", "struct.childproperties", "struct.propertiessize",
        "class.cdo", "enum.names",
        "function.paramssize", "function.flags", "function.func",
    };
    std::map<std::string, u32*> out;
    for (const char* k : keys) {
        u32* p = Bind(k);
        if (p) out[k] = p;
    }
    return out;
}

std::map<std::string, bool*> UEOffsets::BindAllBool() {
    std::map<std::string, bool*> out;
    out["array.flat"] = &oaFlat;
    out["ffield.enabled"] = &useFFields;
    return out;
}

void UEOffsets::SetDefaultsFor(const UEVersion& v) {
    // reset, then specialize. Declared member defaults == UE5 / UE4.25+ FField model.
    *this = UEOffsets{};

    if (v.IsUE5()) return;

    if (v.major == 4 && v.minor >= 25) return; // FField model defaults

    // ---- UE4 pre-4.25: UProperty model (no FField, no ChildProperties) ----
    useFFields = false;
    stChildPropsOff = 0;
    stPropsSizeOff = 0x40;
    if (v.minor <= 21) objIndexOff = 0; // InternalIndex not guaranteed pre-4.22 -> probe
}

} // namespace dumper
