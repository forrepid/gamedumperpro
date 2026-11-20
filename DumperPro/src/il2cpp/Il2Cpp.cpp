// ============================================================================
// DumperPro - Il2Cpp.cpp
//
// Unity IL2CPP global-metadata.dat parser.
// Header/struct sirasi ve surum kosullari birebir Il2CppDumper
// (Metadata.cs + MetadataClass.cs) kaynaklarindan dogrulanarak alindi.
//
// Baslica dogrulanmis gercekler:
//   - sanity 0xFAB11BAF; desteklenen metadata surumleri 16..31
//   - header: (offset,size) ciftleri; v<=24.1'de rgctxEntries cifti vardir,
//     v24.2+ yoktur (header layout'u kayar)
//   - Il2CppStringLiteral = { u32 length; i32 dataIndex; } (8 bayt, sabit)
//   - string havuzu: stringOffset'ten NUL-sonlandirilmis
//   - Il2CppTypeDefinition u16 sayaclarinin sirasi: method, property, field,
//     event, nested_type, vtable, interfaces, interface_offsets
//   - Il2CppMethodDefinition: v31'de returnParameterToken eklenir
//
// Struct boyut tablosu (MetadataClass.cs'den hesaplandi, bayt):
//   TypeDefinition : v<=24.0 -> 104 | 24.1 -> 100 | 24.2-24.5 -> 92 | 25+ -> 88
//   MethodDefinition: v<=24.0 -> 56 | 24.1 -> 52 | 25-30 -> 32 | 31 -> 36
//   FieldDefinition : v<=24.0 -> 16 | 24.1+ -> 12
//   ParamDefinition : v<=24.0 -> 16 | 24.1+ -> 12
//   ImageDefinition : v<24 -> 20/24 | 24.0 -> 32 | 24.1+ -> 40
//
// ONEMLI NOTLAR (ONEMLI NOTLAR):
//   - Metadata-yalniz mod: Il2CppType tablosu ve metod native adresleri
//     binarydedir (libil2cpp.so / GameAssembly.dll) oldugu icin tip isimleri
//     yerine TypeIndex yazilir. Bilincli kisaltma, hata degildir.
//   - Kati sinirlar: her okuma sinir kontrollu; surum > 31 veya bozuk
//     sanity dosyasi reddedilir (sessiz tahmin YOK).
// ============================================================================

#include "il2cpp/Il2Cpp.h"
#include "utils/StrUtil.h"
#include "utils/Logger.h"

namespace dumper {

namespace {

constexpr u32 kIl2Sanity = 0xFAB11BAFu;

u16 Rd16(const u8* p) { return (u16)(p[0] | (p[1] << 8)); }
u32 Rd32(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
i32 RdS32(const u8* p) { return (i32)Rd32(p); }

struct SecPair {
    u64 off = 0;
    i64 size = 0;
};

} // namespace

// ---------------------------------------------------------------------------
bool Il2CppMetadataParser::LooksLikeMetadata(const u8* data, size_t size) {
    if (!data || size < 8) return false;
    if (Rd32(data) != kIl2Sanity) return false;
    const i32 ver = RdS32(data + 4);
    return ver >= 0 && ver <= 1000;
}

// ---------------------------------------------------------------------------
bool Il2CppMetadataParser::Parse(const u8* data, size_t size, Il2Metadata& out) {
    out = Il2Metadata{};
    out.fileSize = size;

    if (!data || size < 0x40) {
        out.lastError = "dosya cok kucuk";
        return false;
    }
    if (Rd32(data) != kIl2Sanity) {
        out.lastError = "sanity 0xFAB11BAF eslesmedi (IL2CPP metadata degil)";
        return false;
    }
    const int rawVer = RdS32(data + 4);
    if (rawVer < 16 || rawVer > 31) {
        char b[128];
        snprintf(b, sizeof(b), "desteklenmeyen metadata surumu: %d (desteklenen: 16..31)", rawVer);
        out.lastError = b;
        return false;
    }
    out.version = rawVer;

    double verF = (double)rawVer; // 24 alt surumleri icin kesirli karsilastirma

    // ---- v24 alt-surum tespiti (Il2CppDumper Metadata.cs ile ayni) ----------
    // stringLiteralOffset header'in ilk bolum ciftidir (surumden bagimsiz
    // konum: 2. i32 cifti = +8); degeri 264 olan v24 dosyalari v24.2 duzenidir.
    bool ver242 = false;
    if (rawVer == 24 && size >= 0x18 && RdS32(data + 8) == 264) ver242 = true;
    if (ver242) verF = 24.2;

    // ---- header'i surume gore oku (MetadataClass.cs alan sirasi) ------------
    SecPair stringLiteral, stringLiteralData, strings, events, properties,
            methods, parameterDefaultValues, fieldDefaultValues,
            fieldAndParamDefData, fieldMarshaledSizes, parameters, fields,
            genericParameters, genericParameterConstraints, genericContainers,
            nestedTypes, interfaces, vtableMethods, interfaceOffsets,
            typeDefinitions, rgctxEntries, images, assemblies,
            metadataUsageLists, metadataUsagePairs, fieldRefs,
            referencedAssemblies, attributesInfo, attributeTypes,
            attributeData, attributeDataRange, unresolvedVCallTypes,
            unresolvedVCallRanges, windowsRuntimeTypeNames,
            windowsRuntimeStrings, exportedTypeDefinitions;

    size_t hpos = 8; // header imleci (sanity+version sonrasi)
    auto pair = [&](SecPair& s) {
        if (hpos + 8 > size) { s = SecPair{}; return; }
        s.off = Rd32(data + hpos);
        s.size = RdS32(data + hpos + 4);
        hpos += 8;
    };

    pair(stringLiteral);
    pair(stringLiteralData);
    pair(strings);
    pair(events);
    pair(properties);
    pair(methods);
    pair(parameterDefaultValues);
    pair(fieldDefaultValues);
    pair(fieldAndParamDefData);
    pair(fieldMarshaledSizes);
    pair(parameters);
    pair(fields);
    pair(genericParameters);
    pair(genericParameterConstraints);
    pair(genericContainers);
    pair(nestedTypes);
    pair(interfaces);
    pair(vtableMethods);
    pair(interfaceOffsets);
    pair(typeDefinitions);
    if (verF <= 24.1) pair(rgctxEntries);           // [Max = 24.1]
    pair(images);
    pair(assemblies);
    if (verF >= 19.0 && verF <= 24.5) {             // [Min=19, Max=24.5]
        pair(metadataUsageLists);
        pair(metadataUsagePairs);
    }
    if (verF >= 19.0) pair(fieldRefs);              // [Min = 19]
    if (verF >= 20.0) pair(referencedAssemblies);   // [Min = 20]
    if (verF >= 21.0 && verF <= 27.2) { pair(attributesInfo); pair(attributeTypes); }
    if (verF >= 29.0) { pair(attributeData); pair(attributeDataRange); }
    if (verF >= 22.0) { pair(unresolvedVCallTypes); pair(unresolvedVCallRanges); }
    if (verF >= 23.0) pair(windowsRuntimeTypeNames);
    if (verF >= 27.0) pair(windowsRuntimeStrings);
    if (verF >= 24.0) pair(exportedTypeDefinitions); // [Min = 24]

    if (hpos > size) {
        out.lastError = "header kesik/bozuk";
        return false;
    }

    // header bitti; ilk bolum offset'i header sonunun en az o kadar uzak olmali
    if (stringLiteral.off < hpos || stringLiteral.off > size) {
        out.lastError = "header bolum offsetleri tutarsiz";
        return false;
    }

    out.stringLiteralDataSize = (u64)stringLiteralData.size;
    out.stringDataSize = (u64)strings.size;

    // ---- struct boyutlari (surum kesinlestikten sonra; 24.1 tespiti asagida) --
    auto ComputeSizes = [&](double vf, int rv, u32& typeDefSize, u32& methodDefSize,
                            u32& fieldDefSize, u32& paramDefSize, u32& propDefSize,
                            u32& eventDefSize, u32& imageDefSize) {
        // Il2CppTypeDefinition: name,ns[,customAttr][,byref],declaring,parent,
        // element[,rgctxS,rgctxC],generic,flags, 8*start, 8*u16, bitfield[,token]
        if (vf <= 24.0)       typeDefSize = 104;
        else if (vf <= 24.1)  typeDefSize = 100;
        else if (vf < 25.0)   typeDefSize = 92;
        else                  typeDefSize = 88;
        // Il2CppMethodDefinition
        if (vf <= 24.0)       methodDefSize = 56;
        else if (vf <= 24.1)  methodDefSize = 52;
        else if (vf < 31.0)   methodDefSize = 32;
        else                  methodDefSize = 36;
        fieldDefSize = (vf <= 24.0) ? 16 : 12;
        paramDefSize = (vf <= 24.0) ? 16 : 12;
        propDefSize  = (vf <= 24.0) ? 24 : 20;
        eventDefSize = (vf <= 24.0) ? 28 : 24;
        if (vf < 24.0)        imageDefSize = (rv >= 19) ? 24 : 20;
        else if (vf < 24.1)   imageDefSize = 32;
        else                  imageDefSize = 40;
    };

    u32 typeDefSize = 0, methodDefSize = 0, fieldDefSize = 0, paramDefSize = 0,
        propDefSize = 0, eventDefSize = 0, imageDefSize = 0;
    ComputeSizes(verF, rawVer, typeDefSize, methodDefSize, fieldDefSize,
                 paramDefSize, propDefSize, eventDefSize, imageDefSize);

    // ---- images ile v24.1 tespiti (Il2CppDumper: image token != 1) -----------
    // v24.0'da imageDefSize=32; token ofseti 28. Token'u 1'den farkli bir kayit
    // varsa layout 24.1'dir (stride 40; token ofseti yine 28).
    if (rawVer == 24 && verF == 24.0) {
        const u64 n32 = (images.size >= 0) ? ((u64)images.size / 32) : 0;
        if (n32 > 0 && (u64)images.off + n32 * 32 <= size) {
            bool anyNe1 = false;
            for (u64 i = 0; i < n32; i++) {
                const u32 tok = Rd32(data + images.off + i * 32 + 28);
                if (tok != 1) { anyNe1 = true; break; }
            }
            if (anyNe1) {
                verF = 24.1;
                ComputeSizes(verF, rawVer, typeDefSize, methodDefSize, fieldDefSize,
                             paramDefSize, propDefSize, eventDefSize, imageDefSize);
            }
        }
    }

    // ---- surum etiketi + yaklasik Unity araligi -------------------------------
    {
        char vb[32];
        if (verF == 24.2)      snprintf(vb, sizeof(vb), "24.2");
        else if (verF == 24.1) snprintf(vb, sizeof(vb), "24.1");
        else                   snprintf(vb, sizeof(vb), "%d", rawVer);
        out.versionStr = vb;
    }
    if (verF < 18)      out.unityHint = "Unity ~5.3-5.5";
    else if (verF < 19) out.unityHint = "Unity ~5.5";
    else if (verF < 20) out.unityHint = "Unity ~5.6";
    else if (verF < 21) out.unityHint = "Unity ~2017.1";
    else if (verF < 22) out.unityHint = "Unity ~2017.2";
    else if (verF < 23) out.unityHint = "Unity ~2017.3-2017.4";
    else if (verF < 24) out.unityHint = "Unity ~2018.1-2018.2";
    else if (verF < 24.1) out.unityHint = "Unity ~2018.3-2019.1";
    else if (verF < 24.2) out.unityHint = "Unity ~2019.2";
    else if (verF < 24.4) out.unityHint = "Unity ~2019.3-2019.4";
    else if (verF < 24.5) out.unityHint = "Unity ~2020.1";
    else if (verF < 25) out.unityHint = "Unity ~2020.1-2020.2";
    else if (verF < 27) out.unityHint = "Unity ~2020.2";
    else if (verF < 27.1) out.unityHint = "Unity ~2020.2-2021.1";
    else if (verF < 27.2) out.unityHint = "Unity ~2021.1";
    else if (verF < 29) out.unityHint = "Unity ~2021.2-2021.3";
    else if (verF < 31) out.unityHint = "Unity ~2022.1-2022.2";
    else                out.unityHint = "Unity ~2022.3+ / Unity 6";

    // ---- bolum kayit sayilari --------------------------------------------------
    auto CountOf = [&](const SecPair& s, u32 elem) -> u64 {
        if (s.size < 0 || elem == 0) return 0;
        return (u64)s.size / elem;
    };
    const u64 imageCount  = CountOf(images, imageDefSize);
    const u64 typeCount   = CountOf(typeDefinitions, typeDefSize);
    const u64 fieldCount  = CountOf(fields, fieldDefSize);
    const u64 methodCount = CountOf(methods, methodDefSize);
    const u64 paramCount  = CountOf(parameters, paramDefSize);
    const u64 propCount   = CountOf(properties, propDefSize);
    const u64 eventCount  = CountOf(events, eventDefSize);
    const u64 litCount    = CountOf(stringLiteral, 8);
    (void)propCount; (void)eventCount;

    // sacma sayilar -> bozuk stride/dosya
    if (typeCount > 4000000 || fieldCount > 20000000 || methodCount > 20000000) {
        out.lastError = "bolum boyutlari tutarsiz (stride yanlis olabilir)";
        return false;
    }

    // ---- string havuzu erisimi ---------------------------------------------------
    auto GetString = [&](u32 idx) -> std::string {
        if (idx == 0xFFFFFFFFu) return "";
        const u64 base = (u64)strings.off + idx;
        if (idx >= (u64)strings.size || base >= size) return "";
        const u64 maxLen = std::min<u64>(size - base, 512);
        const u8* p = data + base;
        size_t len = 0;
        while (len < maxLen && p[len] != 0) len++;
        return std::string((const char*)p, len);
    };

    // ---- images --------------------------------------------------------------------
    out.images.reserve((size_t)std::min<u64>(imageCount, 65536));
    for (u64 i = 0; i < imageCount; i++) {
        const u64 recOff = (u64)images.off + i * imageDefSize;
        if (recOff + imageDefSize > size) break;
        const u8* rec = data + recOff;
        Il2ImageInfo im;
        const u32 nameIdx = Rd32(rec);
        im.typeStart = (u32)std::max<i32>(RdS32(rec + 8), 0);
        im.typeCount = Rd32(rec + 12);
        if (verF < 24.0) {
            im.token = Rd32(rec + 20);            // name,aIdx,tStart,tCount,ep,token
        } else {
            im.token = Rd32(rec + 28);            // +exportedType ciftleri; token hala 28
        }
        im.name = GetString(nameIdx);
        if (im.name.empty()) im.name = "<image_" + std::to_string(i) + ">";
        out.images.push_back(std::move(im));
    }

    // ---- type definitions ------------------------------------------------------------
    out.types.reserve((size_t)std::min<u64>(typeCount, 400000));
    for (u64 i = 0; i < typeCount; i++) {
        const u64 recOff = (u64)typeDefinitions.off + i * typeDefSize;
        if (recOff + typeDefSize > size) break;
        const u8* rec = data + recOff;
        size_t f = 0; // i32 adimli alan imleci
        auto nextI = [&]() -> i32 {
            const i32 v = RdS32(rec + f * 4);
            f++;
            return v;
        };

        Il2TypeInfo t;
        const u32 nameIdx = (u32)nextI();      // nameIndex
        const u32 nsIdx   = (u32)nextI();      // namespaceIndex
        if (verF <= 24.0) nextI();             // customAttributeIndex [Max=24]
        nextI();                               // byvalTypeIndex
        if (verF < 25.0) nextI();              // byrefTypeIndex [Max=24.5]
        const i32 declaring = nextI();         // declaringTypeIndex
        const i32 parent    = nextI();         // parentIndex
        nextI();                               // elementTypeIndex
        if (verF <= 24.1) { nextI(); nextI(); }// rgctxStartIndex, rgctxCount
        nextI();                               // genericContainerIndex
        const u32 flags = Rd32(rec + f * 4); f++;
        const i32 fieldStart  = nextI();
        const i32 methodStart = nextI();
        nextI();                               // eventStart
        nextI();                               // propertyStart
        nextI();                               // nestedTypesStart
        nextI();                               // interfacesStart
        nextI();                               // vtableStart
        nextI();                               // interfaceOffsetsStart
        const u16 methodCnt   = Rd16(rec + f * 4);
        const u16 propertyCnt = Rd16(rec + f * 4 + 2);
        f += 1;                                // method+property cifti = 2 u16 = 1 i32 slot
        const u16 fieldCnt    = Rd16(rec + f * 4);
        const u16 eventCnt    = Rd16(rec + f * 4 + 2);
        f += 1;                                // field+event cifti
        f += 2;                               // nested/vtable/interfaces/ifoffset (4 u16 = 2 slot)
        const u32 bitfield = Rd32(rec + f * 4); f++;
        u32 token = 0;
        if (rawVer >= 19) { token = Rd32(rec + f * 4); f++; }
        (void)declaring;

        t.name = GetString(nameIdx);
        t.ns = GetString(nsIdx);
        t.parentIndex = parent;
        t.flags = flags;
        t.fieldStart = (u32)std::max(fieldStart, 0);
        t.methodStart = (u32)std::max(methodStart, 0);
        t.fieldCount = fieldCnt;
        t.methodCount = methodCnt;
        t.propertyCount = propertyCnt;
        t.eventCount = eventCnt;
        t.isValueType = (bitfield & 1u) != 0;
        t.isEnum = ((bitfield >> 1) & 1u) != 0;
        t.isInterface = (flags & 0x20u) != 0;
        t.token = token;
        out.types.push_back(std::move(t));
    }

    // ---- fields ------------------------------------------------------------------------
    out.fields.reserve((size_t)std::min<u64>(fieldCount, 400000));
    for (u64 i = 0; i < fieldCount; i++) {
        const u64 recOff = (u64)fields.off + i * fieldDefSize;
        if (recOff + fieldDefSize > size) break;
        const u8* rec = data + recOff;
        Il2FieldInfo fl;
        const u32 nameIdx = Rd32(rec);
        fl.typeIndex = RdS32(rec + 4);
        fl.token = (verF <= 24.0) ? Rd32(rec + 12) : Rd32(rec + 8);
        fl.name = GetString(nameIdx);
        out.fields.push_back(std::move(fl));
    }

    // ---- methods -----------------------------------------------------------------------
    out.methods.reserve((size_t)std::min<u64>(methodCount, 400000));
    for (u64 i = 0; i < methodCount; i++) {
        const u64 recOff = (u64)methods.off + i * methodDefSize;
        if (recOff + methodDefSize > size) break;
        const u8* rec = data + recOff;
        Il2MethodInfo mi;
        const u32 nameIdx = Rd32(rec);
        mi.returnTypeIndex = RdS32(rec + 8);
        if (verF >= 31.0) {
            // name,decl,ret,returnParamToken,paramStart,generic,token,flags,iflags,slot,pCount
            mi.parameterStart = RdS32(rec + 16);
            mi.token = Rd32(rec + 24);
            mi.flags = Rd16(rec + 28);
            mi.iflags = Rd16(rec + 30);
            mi.slot = Rd16(rec + 32);
            mi.parameterCount = Rd16(rec + 34);
        } else if (verF <= 24.0) {
            // v16-24.0 (56 bayt) - Il2CppDumper MetadataClass.cs alan sirasi:
            // name(0),decl(4),ret(8),paramStart(12),customAttr(16),generic(20),
            // methodIdx(24),invoker(28),dw(32),rgctxS(36),rgctxC(40),
            // token(44),flags(48 u16),iflags(50),slot(52),pCount(54)
            mi.parameterStart = RdS32(rec + 12);
            mi.token = Rd32(rec + 44);
            mi.flags = Rd16(rec + 48);
            mi.iflags = Rd16(rec + 50);
            mi.slot = Rd16(rec + 52);
            mi.parameterCount = Rd16(rec + 54);
        } else if (verF <= 24.1) {
            // name,decl,ret,paramStart,generic,methodIdx,invoker,dw,rgctxS,rgctxC,token,flags...
            mi.parameterStart = RdS32(rec + 12);
            mi.token = Rd32(rec + 40);
            mi.flags = Rd16(rec + 44);
            mi.iflags = Rd16(rec + 46);
            mi.slot = Rd16(rec + 48);
            mi.parameterCount = Rd16(rec + 50);
        } else { // v25-30 (0x20)
            // name,decl,ret,paramStart,generic,token,flags,iflags,slot,pCount
            mi.parameterStart = RdS32(rec + 12);
            mi.token = Rd32(rec + 20);
            mi.flags = Rd16(rec + 24);
            mi.iflags = Rd16(rec + 26);
            mi.slot = Rd16(rec + 28);
            mi.parameterCount = Rd16(rec + 30);
        }
        mi.name = GetString(nameIdx);
        out.methods.push_back(std::move(mi));
    }

    // ---- parameters ----------------------------------------------------------------------
    out.params.reserve((size_t)std::min<u64>(paramCount, 400000));
    for (u64 i = 0; i < paramCount; i++) {
        const u64 recOff = (u64)parameters.off + i * paramDefSize;
        if (recOff + paramDefSize > size) break;
        const u8* rec = data + recOff;
        Il2ParamInfo pi;
        const u32 nameIdx = Rd32(rec);
        pi.typeIndex = (verF <= 24.0) ? RdS32(rec + 12) : RdS32(rec + 8);
        pi.name = GetString(nameIdx);
        out.params.push_back(std::move(pi));
    }

    // ---- metadataUsages (yalnizca metadata v19..24.5) --------------------------------------
    // Il2CppDumper Metadata.cs ProcessingMetadataUsage ile ayni akis:
    // list'ler pair dizisine gruplar; her pair (destinationIndex, encodedSourceIndex)
    // tipi ve indexi cozer. metadata v27+ bu tablolari tamamen kaldirdi.
    const bool usagesInVer = (rawVer >= 19 && rawVer <= 24);
    std::unordered_set<u32> neededLiterals;   // StringLiteral usage indexleri
    std::unordered_set<u32> neededFieldRefs;  // FieldInfo usage indexleri
    if (usagesInVer) {
        auto CountOfSz = [&](const SecPair& s) -> u64 {
            if (s.size < 0 || s.off > size) return 0;
            return (u64)s.size / 8;
        };
        const u64 listCount = CountOfSz(metadataUsageLists);
        const u64 pairCount = CountOfSz(metadataUsagePairs);
        if (listCount > 0 && pairCount > 0 && pairCount <= 8000000) {
            std::vector<Il2UsagePair> decoded;
            decoded.reserve((size_t)std::min<u64>(pairCount, 2000000));
            bool any = false;
            u32 maxDest = 0;
            for (u64 li = 0; li < listCount; li++) {
                const u64 lOff = (u64)metadataUsageLists.off + li * 8;
                if (lOff + 8 > size) break;
                const u32 start = Rd32(data + lOff);
                const u32 cnt   = Rd32(data + lOff + 4);
                if ((u64)start + cnt > pairCount) continue; // grup tasmasi -> atla
                for (u32 k = 0; k < cnt; k++) {
                    const u64 pOff = (u64)metadataUsagePairs.off + (u64)(start + k) * 8;
                    if (pOff + 8 > size) break;
                    const u32 dest  = Rd32(data + pOff);
                    const u32 enc   = Rd32(data + pOff + 4);
                    Il2UsagePair up;
                    up.destinationIndex = dest;
                    up.usageType    = (enc & 0xE0000000u) >> 29;
                    up.decodedIndex = enc & 0x1FFFFFFFu;
                    if (up.usageType < 1 || up.usageType > 6) continue;
                    if (dest > maxDest) maxDest = dest;
                    if (up.usageType == 5) neededLiterals.insert(up.decodedIndex);
                    if (up.usageType == 4) neededFieldRefs.insert(up.decodedIndex);
                    decoded.push_back(up);
                    any = true;
                }
            }
            if (any) {
                out.hasUsages = true;
                out.usages = std::move(decoded);
                out.usageSlotCount = maxDest + 1;
            }
        }

        // fieldRefs tablosu (Il2CppFieldRef { i32 typeIndex; i32 fieldIndex; }, 8 bayt)
        // yalnizca usage'larca referans edilen kayitlar saklanir (bellek controlu).
        const u64 frCount = (fieldRefs.size > 0 && fieldRefs.off < size)
                            ? (u64)fieldRefs.size / 8 : 0;
        out.fieldRefCount = (u32)std::min<u64>(frCount, 0xFFFFFFFFu);
        if (frCount > 0 && !neededFieldRefs.empty()) {
            for (u32 idx : neededFieldRefs) {
                if ((u64)idx >= frCount) continue;
                const u64 rOff = (u64)fieldRefs.off + (u64)idx * 8;
                if (rOff + 8 > size) continue;
                Il2FieldRefInfo fr;
                fr.typeIndex  = RdS32(data + rOff);
                fr.fieldIndex = RdS32(data + rOff + 4);
                out.usageFieldRefs.emplace(idx, fr);
            }
        }
    }

    // ---- string literals (cap'li ornek) ----------------------------------------------------
    out.stringLiteralCount = (u32)litCount;
    const u64 litCap = std::min<u64>(litCount, 100000);
    out.stringLiterals.reserve((size_t)litCap);
    for (u64 i = 0; i < litCap; i++) {
        const u64 recOff = (u64)stringLiteral.off + i * 8;
        if (recOff + 8 > size) break;
        const u32 len = Rd32(data + recOff);
        const i32 dIdx = RdS32(data + recOff + 4);
        if (len == 0 || len > 4096 || dIdx < 0) { out.stringLiterals.push_back(""); continue; }
        const u64 base = (u64)stringLiteralData.off + (u64)dIdx;
        if (base + len > size) { out.stringLiterals.push_back(""); continue; }
        out.stringLiterals.emplace_back((const char*)(data + base), len);
    }

    // usage'larin referans ettigi literal degerleri (cap'siz - yalnizca ihtiyac duyulanlar)
    if (out.hasUsages && !neededLiterals.empty()) {
        for (u32 idx : neededLiterals) {
            if ((u64)idx >= litCount) continue;
            const u64 recOff = (u64)stringLiteral.off + (u64)idx * 8;
            if (recOff + 8 > size) continue;
            const u32 len = Rd32(data + recOff);
            const i32 dIdx = RdS32(data + recOff + 4);
            if (len == 0 || len > 4096 || dIdx < 0) continue;
            const u64 base = (u64)stringLiteralData.off + (u64)dIdx;
            if (base + len > size) continue;
            out.usageStringLiterals.emplace(idx, std::string((const char*)(data + base), len));
        }
    }

    out.valid = true;
    return true;
}

// ---------------------------------------------------------------------------
// rapor / json / dump.cs uretimi
// ---------------------------------------------------------------------------

static std::string JsonEsc(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 16);
    for (unsigned char ch : in) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", ch); out += b; }
                else out += (char)ch;
        }
    }
    return out;
}

static std::string KindOf(const Il2TypeInfo& t) {
    if (t.isEnum) return "enum";
    if (t.isInterface) return "interface";
    if (t.isValueType) return "struct";
    return "class";
}

static std::string ModifiersOf(const Il2TypeInfo& t) {
    std::string m = "public";
    if (t.flags & 0x80u) m += " abstract";
    if (t.flags & 0x100u) m += " sealed";
    return m;
}

static std::string MethodAccess(u16 flags) {
    switch (flags & 0x7u) {
        case 6: return "public";
        case 4: return "protected";
        case 3: return "internal";
        default: return "private";
    }
}

static std::string FieldAccess(u16 flags) {
    switch (flags & 0x7u) {
        case 6: return "public";
        case 4: return "protected";
        case 3: return "internal";
        default: return "private";
    }
}

static std::string HumanSizeIl2(u64 b) {
    char buf[64];
    if (b < 1024) snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
    else if (b < 1024ull * 1024) snprintf(buf, sizeof(buf), "%.1f KB", (double)b / 1024);
    else if (b < 1024ull * 1024 * 1024) snprintf(buf, sizeof(buf), "%.1f MB", (double)b / (1024 * 1024));
    else snprintf(buf, sizeof(buf), "%.2f GB", (double)b / (1024 * 1024 * 1024));
    return buf;
}

static std::string HexToken(u32 t) {
    char b[16];
    snprintf(b, sizeof(b), "0x%08X", t);
    return b;
}

std::string Il2CppMetadataParser::BuildReport(const Il2Metadata& m, const std::string& fileName) {
    std::vector<std::string> L;
    auto H = [&](const std::string& t) {
        std::string line(64, '=');
        L.push_back(line); L.push_back(t); L.push_back(line);
    };

    H("DumperPro - IL2CPP Metadata Raporu");
    L.push_back("Dosya            : " + fileName);
    L.push_back("Boyut            : " + HumanSizeIl2(m.fileSize));
    L.push_back("Durum            : " + std::string(m.valid ? "GECERLI (sanity 0xFAB11BAF)" : "GECERSIZ: " + m.lastError));
    L.push_back("Metadata surumu  : " + m.versionStr +
                (m.unityHint.empty() ? "" : "  (" + m.unityHint + ", yaklasik)"));
    L.push_back("");

    H("SAYIMLAR");
    L.push_back("Image/Assembly  : " + std::to_string(m.images.size()));
    L.push_back("Tip tanimi      : " + std::to_string(m.types.size()));
    L.push_back("Alan (field)    : " + std::to_string(m.fields.size()));
    L.push_back("Metod           : " + std::to_string(m.methods.size()));
    L.push_back("Parametre       : " + std::to_string(m.params.size()));
    L.push_back("String literal  : " + std::to_string(m.stringLiteralCount) +
                "  (gosterilen: " + std::to_string(m.stringLiterals.size()) + ")");
    if (m.hasUsages)
        L.push_back("Metadata usages : " + std::to_string(m.usages.size()) +
                    " pair  slot=" + std::to_string(m.usageSlotCount) +
                    "  (v19-24.5; binary eslestirmede hucre isimleri cozulur)");
    L.push_back("");

    if (!m.images.empty()) {
        H("IMAGES (assembly basina tip araliklari)");
        const size_t cap = std::min<size_t>(m.images.size(), 30);
        for (size_t i = 0; i < cap; i++) {
            const Il2ImageInfo& im = m.images[i];
            char b[300];
            snprintf(b, sizeof(b), "  %-40s tipler=[%u..%u)  token=%s",
                     im.name.substr(0, 40).c_str(), im.typeStart,
                     im.typeStart + im.typeCount, HexToken(im.token).c_str());
            L.push_back(b);
        }
        if (m.images.size() > cap)
            L.push_back("  ... (+" + std::to_string(m.images.size() - cap) + " daha)");
        L.push_back("");
    }

    if (!m.types.empty()) {
        H("TIPLER (ilk 40, kind/uye sayilari)");
        const size_t cap = std::min<size_t>(m.types.size(), 40);
        for (size_t i = 0; i < cap; i++) {
            const Il2TypeInfo& t = m.types[i];
            std::string full = t.ns.empty() ? t.name : t.ns + "." + t.name;
            if (full.empty()) full = "<anon_" + std::to_string(i) + ">";
            char b[300];
            snprintf(b, sizeof(b), "  %-52s %-9s f=%-5u m=%-5u token=%s",
                     full.substr(0, 52).c_str(), KindOf(t).c_str(),
                     t.fieldCount, t.methodCount, HexToken(t.token).c_str());
            L.push_back(b);
        }
        if (m.types.size() > cap)
            L.push_back("  ... (+" + std::to_string(m.types.size() - cap) + " daha)");
        L.push_back("");
    }

    if (!m.stringLiterals.empty()) {
        H("STRING LITERAL ORNEKLERI (ilk 20)");
        size_t shown = 0;
        for (const std::string& s : m.stringLiterals) {
            if (shown >= 20) break;
            if (s.empty()) continue;
            std::string one = s;
            if (one.size() > 80) one = one.substr(0, 77) + "...";
            L.push_back("  \"" + one + "\"");
            shown++;
        }
        L.push_back("");
    }

    H("NOTLAR");
    L.push_back("  - Metadata-yalniz mod: Il2CppType tablosu ve metod native adresleri");
    L.push_back("    binarydedir (libil2cpp.so / GameAssembly.dll). Alan/metod tipleri");
    L.push_back("    TypeIndex olarak yazilir; binary eslestirmesi yol haritasindadir.");
    L.push_back("  - Unity surum tahmini metadata surumunden yaklasiktir; garanti degildir.");
    L.push_back("  - il2cpp_dump.cs iskelet cikti, il2cpp_metadata.json makine-okur semadir.");
    L.push_back("  - Yasal sinir: yalnizca sahibi olunan/lisansli yazilimin analizi.");
    return str::Join(L, "\n") + "\n";
}

std::string Il2CppMetadataParser::BuildJson(const Il2Metadata& m, const std::string& fileName) {
    constexpr u64 kTypeCap = 100000;
    const bool truncated = (u64)m.types.size() > kTypeCap;

    std::string j;
    j.reserve(2 << 20);
    j += "{\n";
    j += "  \"tool\": \"DumperPro\",\n";
    j += "  \"file\": \"" + JsonEsc(fileName) + "\",\n";
    j += "  \"format\": \"il2cpp-metadata\",\n";
    j += "  \"metadataVersion\": \"" + JsonEsc(m.versionStr) + "\",\n";
    j += "  \"unityHint\": \"" + JsonEsc(m.unityHint) + "\",\n";
    j += "  \"fileSize\": " + std::to_string(m.fileSize) + ",\n";
    j += "  \"counts\": {\n";
    j += "    \"images\": " + std::to_string(m.images.size()) + ",\n";
    j += "    \"types\": " + std::to_string(m.types.size()) + ",\n";
    j += "    \"fields\": " + std::to_string(m.fields.size()) + ",\n";
    j += "    \"methods\": " + std::to_string(m.methods.size()) + ",\n";
    j += "    \"parameters\": " + std::to_string(m.params.size()) + ",\n";
    j += "    \"stringLiterals\": " + std::to_string(m.stringLiteralCount) + "\n";
    j += "  },\n";

    j += "  \"images\": [\n";
    for (size_t i = 0; i < m.images.size(); i++) {
        const Il2ImageInfo& im = m.images[i];
        j += "    {\"name\": \"" + JsonEsc(im.name) + "\", \"typeStart\": " +
             std::to_string(im.typeStart) + ", \"typeCount\": " +
             std::to_string(im.typeCount) + ", \"token\": \"" + HexToken(im.token) + "\"}";
        if (i + 1 < m.images.size()) j += ",";
        j += "\n";
    }
    j += "  ],\n";

    j += "  \"types\": [\n";
    for (size_t i = 0; i < m.types.size() && (u64)i < kTypeCap; i++) {
        const Il2TypeInfo& t = m.types[i];
        char fl[32];
        snprintf(fl, sizeof(fl), "0x%08X", t.flags);
        j += "    {\"name\": \"" + JsonEsc(t.name) + "\", \"namespace\": \"" +
             JsonEsc(t.ns) + "\", \"kind\": \"" + KindOf(t) +
             "\", \"flags\": \"" + fl + "\", \"fields\": " +
             std::to_string(t.fieldCount) + ", \"methods\": " +
             std::to_string(t.methodCount) + ", \"token\": \"" + HexToken(t.token) + "\"}";
        if (i + 1 < m.types.size() && (u64)(i + 1) < kTypeCap) j += ",";
        j += "\n";
    }
    j += "  ],\n";
    j += "  \"typesTruncated\": " + std::string(truncated ? "true" : "false") + ",\n";
    j += "  \"typeResolution\": \"metadata-only (Il2CppType tablosu binary'dedir)\"\n";
    j += "}\n";
    return j;
}

std::string Il2CppMetadataParser::BuildDumpCs(const Il2Metadata& m) {
    std::string o;
    o.reserve(4 << 20);
    o += "// DumperPro IL2CPP dump.cs benzeri cikti\n";
    o += "// metadata surumu: " + m.versionStr +
         (m.unityHint.empty() ? "" : "  (" + m.unityHint + ")") + "\n";
    o += "// NOT: metadata-yalniz mod - tip isimleri yerine TypeIndex (T<idx>) yazilir\n";
    o += "// Il2CppType cozumu icin libil2cpp.so / GameAssembly.dll eslestirmesi gerekir\n\n";

    for (size_t i = 0; i < m.types.size(); i++) {
        const Il2TypeInfo& t = m.types[i];
        o += "// TypeDefinition #" + std::to_string(i) +
             "  token=" + HexToken(t.token) + "\n";
        if (!t.ns.empty()) o += "namespace " + t.ns + "\n{\n";
        o += ModifiersOf(t) + " " + KindOf(t) + " " + (t.name.empty() ? "<anon>" : t.name) + "\n{\n";

        for (u32 k = 0; k < t.fieldCount && (u64)t.fieldStart + k < m.fields.size(); k++) {
            const Il2FieldInfo& f = m.fields[t.fieldStart + k];
            o += "    " + FieldAccess(f.flags) + (f.flags & 0x10u ? " static" : "") +
                 " T<" + std::to_string(f.typeIndex) + "> " +
                 (f.name.empty() ? "<field>" : f.name) + "; // token=" +
                 HexToken(f.token) + "\n";
        }
        for (u32 k = 0; k < t.methodCount && (u64)t.methodStart + k < m.methods.size(); k++) {
            const Il2MethodInfo& mi = m.methods[t.methodStart + k];
            o += "    " + MethodAccess(mi.flags) +
                 (mi.flags & 0x10u ? " static" : "") +
                 (mi.flags & 0x40u ? " virtual" : "") +
                 (mi.flags & 0x400u ? " abstract" : "") +
                 " T<" + std::to_string(mi.returnTypeIndex) + "> " +
                 (mi.name.empty() ? "<method>" : mi.name) + "(";
            for (u32 p = 0; p < mi.parameterCount; p++) {
                const u64 pi = (u64)mi.parameterStart + p;
                if (pi < m.params.size()) {
                    if (p) o += ", ";
                    o += "T<" + std::to_string(m.params[pi].typeIndex) + "> " +
                         (m.params[pi].name.empty() ? "<p>" : m.params[pi].name);
                }
            }
            o += "); // slot=" + std::to_string(mi.slot) + " token=" + HexToken(mi.token) + "\n";
        }
        o += "}\n";
        if (!t.ns.empty()) o += "}\n";
        o += "\n";
    }
    return o;
}

void Il2CppMetadataParser::WriteOutputs(const Il2Metadata& m, const fs::path& outDir,
                                        const std::string& fileName, size_t maxStrings) {
    (void)maxStrings; // stringLiterals Parse icinde cap'li
    std::error_code ec;
    fs::create_directories(outDir, ec);

    {
        std::ofstream f(outDir / "il2cpp_report.txt", std::ios::binary | std::ios::trunc);
        f << BuildReport(m, fileName);
    }
    {
        std::ofstream f(outDir / "il2cpp_dump.cs", std::ios::binary | std::ios::trunc);
        f << BuildDumpCs(m);
    }
    {
        std::ofstream f(outDir / "il2cpp_metadata.json", std::ios::binary | std::ios::trunc);
        f << BuildJson(m, fileName);
    }
    {
        std::ofstream f(outDir / "il2cpp_stringliterals.txt", std::ios::binary | std::ios::trunc);
        f << "; DumperPro - IL2CPP string literals (ilk " << m.stringLiterals.size()
          << " / toplam " << m.stringLiteralCount << ")\n";
        for (const std::string& s : m.stringLiterals) {
            std::string line;
            line.reserve(s.size());
            for (char ch : s) {
                const u8 c = (u8)ch;
                if (c >= 0x20 || c == '\t') line += ch;
                else line += ' ';
            }
            f << line << "\n";
        }
    }
    Log::Ok("IL2CPP outputs -> %s", outDir.string().c_str());
}

} // namespace dumper
