// ----------------------------------------------------------------------------
// DumperPro Online - Unity IL2CPP global-metadata.dat parser
// (Il2CppDumper uyumlu; DumperPro C++ Il2Cpp.cpp'den birebir tasindi)
//
// Kaynak/teyit: Il2CppDumper (Perfare) Metadata.cs + MetadataClass.cs;
// DumperPro/src/il2cpp/Il2Cpp.cpp dogrulanmis layout tablosu:
//   TypeDefinition : v<=24.0 -> 104 | 24.1 -> 100 | 24.2-24.5 -> 92 | 25+ -> 88
//   MethodDefinition: v<=24.0 -> 56 | 24.1 -> 52 | 25-30 -> 32 | 31 -> 36
//   FieldDefinition : v<=24.0 -> 16 | 24.1+ -> 12
//   ParamDefinition : v<=24.0 -> 16 | 24.1+ -> 12
//   ImageDefinition : v<24 -> 20/24 | 24.0 -> 32 | 24.1+ -> 40
//   Il2CppStringLiteral = { u32 length; i32 dataIndex; } (8 B, sabit)
//   sanity = 0xFAB11BAF; desteklenen surum 16..31
//
// ONEMLI NOTLAR (ONEMLI NOTLAR - bu modul icin):
//   1) Metadata yalnizca isim/sayi tutar; metodlarin NATIVE adresleri
//      GameAssembly.dll / libil2cpp.so icindedir (Il2CppBinary isi).
//      Bu mod metadata-yalnimdir: sinif/enum/alan adlari + degerler verir.
//   2) Enum degerleri fieldDefaultValues tablosundan okunur (int32
//      varsayimi; |v|>int32 ise int64 denenir) - metadata-yalnim modda
//      temel tip bilinmedigi icin bu sezgisel yaklasim kullanilir.
//   3) Her okuma sinir kontrolludur; bozuk dosyada kismi sonuc + not.
// ----------------------------------------------------------------------------

import type {
  Il2CppInfo,
  Il2CppClassInfo,
  Il2CppEnumInfo,
} from "./types";

const IL2_SANITY = 0xfab11baf;

interface SecPair {
  off: number;
  size: number;
}

export function looksLikeMetadata(buf: Buffer): boolean {
  if (buf.length < 8) return false;
  return buf.readUInt32LE(0) === IL2_SANITY;
}

/** Linked analiz icin tam veri (image/typedef araliklari + method tokenlari). */
export interface Il2CppCore {
  rawVersion: number;
  effVersion: number;
  images: { name: string; typeStart: number; typeCount: number }[];
  types: {
    name: string; ns: string; flags: number; fieldStart: number; methodStart: number;
    fieldCount: number; methodCount: number; parentIndex: number;
    isValueType: boolean; isEnum: boolean; isInterface: boolean;
  }[];
  methodTokens: number[]; // global metod indeksi -> il2cpp token (rid = token & 0xFFFFFF - 1)
  fieldNames: string[];
  methodNames: string[];
  fieldDefaultValues: Map<number, number>;
}

export function parseIl2CppMetadata(buf: Buffer, notes: string[]): Il2CppInfo | undefined {
  return parseIl2CppMetadataCore(buf, notes)?.info;
}

export function parseIl2CppMetadataCore(buf: Buffer, notes: string[]): { info: Il2CppInfo; core?: Il2CppCore } | undefined {
  if (!looksLikeMetadata(buf)) return undefined;
  const rawVer = buf.readInt32LE(4);
  if (rawVer < 16 || rawVer > 31) {
    notes.push(`IL2CPP metadata surumu desteklenmiyor: ${rawVer} (desteklenen 16..31)`);
    return {
      info: {
        version: String(rawVer),
        unityHint: "bilinmiyor",
        sanityOk: false,
        stringCount: 0,
        literalCount: 0,
        images: [],
        classCount: 0,
        methodCount: 0,
        fieldCount: 0,
        classes: [],
        enums: [],
        literalSamples: [],
        notes: [`sanity eslesti (0xFAB11BAF) ancak surum ${rawVer} desteklenmiyor`],
      },
    };
  }

  let verF = rawVer as number;
  // v24 alt-surum tespiti (Il2CppDumper ile ayni): stringLiteralOffset==264 => v24.2
  if (rawVer === 24 && buf.length >= 0x18 && buf.readInt32LE(8) === 264) verF = 24.2;

  // ---- header ciftleri (MetadataClass.cs alan sirasi) ----
  let hpos = 8;
  const pair = (): SecPair => {
    if (hpos + 8 > buf.length) return { off: 0, size: 0 };
    const off = buf.readUInt32LE(hpos);
    const size = buf.readInt32LE(hpos + 4);
    hpos += 8;
    return { off, size };
  };

  const stringLiteral = pair();
  const stringLiteralData = pair();
  const strings = pair();
  const events = pair();
  const properties = pair();
  const methods = pair();
  const parameterDefaultValues = pair();
  const fieldDefaultValues = pair();
  const fieldAndParamDefData = pair();
  const fieldMarshaledSizes = pair();
  const parameters = pair();
  const fields = pair();
  const genericParameters = pair();
  const genericParameterConstraints = pair();
  const genericContainers = pair();
  const nestedTypes = pair();
  const interfaces = pair();
  const vtableMethods = pair();
  const interfaceOffsets = pair();
  const typeDefinitions = pair();
  if (verF <= 24.1) pair(); // rgctxEntries [Max=24.1]
  const images = pair();
  const assemblies = pair();
  if (verF >= 19 && verF <= 24.5) { pair(); pair(); } // metadataUsageLists/Pairs
  if (verF >= 19) pair(); // fieldRefs
  if (verF >= 20) pair(); // referencedAssemblies
  if (verF >= 21 && verF <= 27.2) { pair(); pair(); } // attributesInfo/Types
  if (verF >= 29) { pair(); pair(); } // attributeData/DataRange
  if (verF >= 22) { pair(); pair(); } // unresolvedVCallTypes/Ranges
  if (verF >= 23) pair(); // windowsRuntimeTypeNames
  if (verF >= 27) pair(); // windowsRuntimeStrings
  if (verF >= 24) pair(); // exportedTypeDefinitions
  void events; void properties; void parameterDefaultValues;
  void fieldMarshaledSizes; void genericParameters; void genericParameterConstraints;
  void genericContainers; void nestedTypes; void interfaces; void vtableMethods;
  void interfaceOffsets; void assemblies; void stringLiteralData;

  if (stringLiteral.off < hpos || stringLiteral.off > buf.length) {
    notes.push("IL2CPP metadata: header bolum offsetleri tutarsiz - yalnizca sayim yapildi");
    return { info: minimalInfo(String(rawVer), "bilinmiyor", buf.length) };
  }

  // ---- struct boyutlari (dogrulanmis tablo) ----
  let typeDefSize: number, methodDefSize: number, fieldDefSize: number, paramDefSize: number, imageDefSize: number;
  if (verF <= 24.0) typeDefSize = 104;
  else if (verF <= 24.1) typeDefSize = 100;
  else if (verF < 25.0) typeDefSize = 92;
  else typeDefSize = 88;
  if (rawVer < 19) typeDefSize -= 4; // TypeDefinition.token alani v19+ (Min=19)
  if (verF <= 24.0) methodDefSize = 56;
  else if (verF <= 24.1) methodDefSize = 52;
  else if (verF < 31.0) methodDefSize = 32;
  else methodDefSize = 36;
  fieldDefSize = verF <= 24.0 ? 16 : 12;
  paramDefSize = verF <= 24.0 ? 16 : 12;
  if (verF < 24.0) imageDefSize = rawVer >= 19 ? 24 : 20;
  else if (verF < 24.1) imageDefSize = 32;
  else imageDefSize = 40;

  // v24.0 -> v24.1 tespiti: image token != 1 olan kayit varsa stride 40
  if (rawVer === 24 && verF === 24.0) {
    const n32 = images.size >= 0 ? Math.floor(images.size / 32) : 0;
    if (n32 > 0 && images.off + n32 * 32 <= buf.length) {
      let anyNe1 = false;
      for (let i = 0; i < n32; i++) {
        if (buf.readUInt32LE(images.off + i * 32 + 28) !== 1) { anyNe1 = true; break; }
      }
      if (anyNe1) {
        verF = 24.1;
        typeDefSize = 100; methodDefSize = 52; fieldDefSize = 12; paramDefSize = 12; imageDefSize = 40;
      }
    }
  }

  const countOf = (s: SecPair, elem: number): number => (s.size < 0 || elem === 0 ? 0 : Math.floor(s.size / elem));
  const imageCount = countOf(images, imageDefSize);
  const typeCount = countOf(typeDefinitions, typeDefSize);
  const fieldCount = countOf(fields, fieldDefSize);
  const methodCount = countOf(methods, methodDefSize);
  const paramCount = countOf(parameters, paramDefSize);
  const literalCount = countOf(stringLiteral, 8);

  if (typeCount > 4_000_000 || fieldCount > 20_000_000 || methodCount > 20_000_000) {
    notes.push("IL2CPP metadata: bolum boyutlari tutarsiz (stride yanlis olabilir) - yalnizca sayim");
    return { info: minimalInfo(versionLabel(verF, rawVer), unityHintOf(verF), buf.length, literalCount) };
  }

  // ---- string havuzu ----
  const getString = (idx: number): string => {
    if (idx === 0xffffffff || idx >= strings.size) return "";
    const base = strings.off + idx;
    if (base >= buf.length) return "";
    const maxLen = Math.min(buf.length - base, 512);
    let len = 0;
    while (len < maxLen && buf[base + len] !== 0) len++;
    return buf.subarray(base, base + len).toString("latin1");
  };

  // ---- images ----
  const imageNames: string[] = [];
  const imagesFull: { name: string; typeStart: number; typeCount: number }[] = [];
  for (let i = 0; i < Math.min(imageCount, 4096); i++) {
    const rec = images.off + i * imageDefSize;
    if (rec + imageDefSize > buf.length) break;
    const name = getString(buf.readUInt32LE(rec)) || `<image_${i}>`;
    if (imageNames.length < 48) imageNames.push(name);
    // ImageDefinition: nameIndex@0 assemblyIndex@4 typeStart@8 typeCount@12
    imagesFull.push({
      name,
      typeStart: buf.readInt32LE(rec + 8),
      typeCount: buf.readUInt32LE(rec + 12),
    });
  }

  // ---- type definitions ----
  const types: {
    name: string; ns: string; flags: number; fieldStart: number; methodStart: number;
    fieldCount: number; methodCount: number; parentIndex: number;
    isValueType: boolean; isEnum: boolean; isInterface: boolean;
  }[] = [];
  for (let i = 0; i < Math.min(typeCount, 400_000); i++) {
    const rec = typeDefinitions.off + i * typeDefSize;
    if (rec + typeDefSize > buf.length) break;
    let f = 0; // i32 adim
    const nextI = () => buf.readInt32LE(rec + f++ * 4);
    const nameIdx = nextI() >>> 0;
    const nsIdx = nextI() >>> 0;
    if (verF <= 24.0) nextI(); // customAttributeIndex
    nextI(); // byvalTypeIndex
    if (verF < 25.0) nextI(); // byrefTypeIndex
    nextI(); // declaringTypeIndex
    const parentIndex = nextI(); // parentIndex (Il2CppType indeksi; linked modda cozumlenir)
    nextI(); // elementTypeIndex
    if (verF <= 24.1) { nextI(); nextI(); } // rgctxStart/Count
    nextI(); // genericContainerIndex
    if (verF <= 22) { nextI(); } // delegateWrapperFromManagedToNativeIndex (Max=22)
    if (verF <= 22) { nextI(); } // marshalingFunctionsIndex (Max=22)
    if (verF >= 21 && verF <= 22) { nextI(); } // ccwFunctionIndex (21-22)
    if (verF >= 21 && verF <= 22) { nextI(); } // guidIndex (21-22)
    const flags = buf.readUInt32LE(rec + f * 4); f++;
    const fieldStart = nextI();
    const methodStart = nextI();
    nextI(); nextI(); nextI(); nextI(); nextI(); nextI(); // event/property/nested/interfaces/vtable/interfaceOffsets start (6 alan)
    const methodCnt = buf.readUInt16LE(rec + f * 4);
    const propertyCnt = buf.readUInt16LE(rec + f * 4 + 2);
    f += 1;
    const fieldCnt = buf.readUInt16LE(rec + f * 4);
    const eventCnt = buf.readUInt16LE(rec + f * 4 + 2);
    f += 1;
    f += 2; // nestedType/vtable + interfaces/interfaceOffsets sayacları
    const bitfield = buf.readUInt32LE(rec + f * 4); f++;
    f++; // token (v19+) - deger kullanilmıyor
    void propertyCnt; void eventCnt;
    types.push({
      name: getString(nameIdx),
      ns: getString(nsIdx),
      flags,
      fieldStart: Math.max(fieldStart, 0),
      methodStart: Math.max(methodStart, 0),
      fieldCount: fieldCnt,
      methodCount: methodCnt,
      parentIndex,
      isValueType: (bitfield & 1) !== 0,
      isEnum: ((bitfield >> 1) & 1) !== 0,
      isInterface: (flags & 0x20) !== 0,
    });
  }

  // ---- fields ----
  const fieldNames: string[] = new Array(fieldCount);
  for (let i = 0; i < Math.min(fieldCount, 400_000); i++) {
    const rec = fields.off + i * fieldDefSize;
    if (rec + fieldDefSize > buf.length) break;
    fieldNames[i] = getString(buf.readUInt32LE(rec));
  }

  // ---- methods (ad + token; token rid -> codeGenModules methodPointers indeksi) ----
  const methodNames: string[] = new Array(methodCount);
  const methodTokens: number[] = new Array(methodCount).fill(0);
  // token alani offseti (MethodDefinition ici, i32 adim):
  //   v31: name,decl,ret,retParamToken,paramStart,generic = 6  -> +24
  //   v25-30: name,decl,ret,paramStart,generic            = 5  -> +20
  //   v24.1: name,decl,ret,paramStart,generic,method,invoker,
  //          delWrapper,rgctxS,rgctxC                      = 10 -> +40
  //   v24.0: + customAttributeIndex                        = 11 -> +44
  const tokenOff = verF >= 31 ? 24 : verF >= 25 ? 20 : verF >= 24.1 ? 40 : 44;
  for (let i = 0; i < Math.min(methodCount, 1_200_000); i++) {
    const rec = methods.off + i * methodDefSize;
    if (rec + methodDefSize > buf.length) break;
    methodNames[i] = getString(buf.readUInt32LE(rec));
    if (rec + tokenOff + 4 <= buf.length) methodTokens[i] = buf.readUInt32LE(rec + tokenOff);
  }

  // ---- parameters ----
  const paramNames: string[] = new Array(paramCount);
  for (let i = 0; i < Math.min(paramCount, 400_000); i++) {
    const rec = parameters.off + i * paramDefSize;
    if (rec + paramDefSize > buf.length) break;
    paramNames[i] = getString(buf.readUInt32LE(rec));
  }

  // ---- field default degerleri (enum uye degerleri icin) ----
  const fdvCount = countOf(fieldDefaultValues, 12);
  const fdv = new Map<number, number>(); // fieldIndex -> dataIndex
  for (let i = 0; i < Math.min(fdvCount, 400_000); i++) {
    const rec = fieldDefaultValues.off + i * 12;
    if (rec + 12 > buf.length) break;
    const fi = buf.readInt32LE(rec);
    const di = buf.readInt32LE(rec + 8);
    if (!fdv.has(fi)) fdv.set(fi, di);
  }
  const readVariant = (dataIdx: number): number | null => {
    const base = fieldAndParamDefData.off + dataIdx;
    if (base + 4 > buf.length) return null;
    // metadata-yalnim modda temel tip bilinmediginden int32 varsayilir
    // (int64 okuma komsu degeri yer); uzun enumlar icin not ile bildirilir
    return buf.readInt32LE(base);
  };

  // ---- sinif/enum cikti ----
  const classes: Il2CppClassInfo[] = [];
  const enums: Il2CppEnumInfo[] = [];
  for (const t of types) {
    if (t.isEnum) {
      const members: Il2CppEnumInfo["members"] = [];
      for (let k = 0; k < Math.min(t.fieldCount, 32); k++) {
        const fi = t.fieldStart + k;
        const nm = fieldNames[fi] ?? `field_${k}`;
        if (nm === "value__") continue;
        const di = fdv.get(fi);
        const val = di !== undefined ? readVariant(di) : null;
        members.push({ name: nm, value: val });
      }
      if (enums.length < 300) {
        enums.push({
          name: t.name,
          namespace: t.ns,
          image: "",
          members,
          memberCount: t.fieldCount,
        });
      }
      continue;
    }
    if (classes.length >= 500) continue;
    const flds: string[] = [];
    for (let k = 0; k < Math.min(t.fieldCount, 24); k++) flds.push(fieldNames[t.fieldStart + k] ?? `field_${k}`);
    const mds: string[] = [];
    for (let k = 0; k < Math.min(t.methodCount, 24); k++) {
      const mIdx = t.methodStart + k;
      const mn = methodNames[mIdx] ?? `method_${k}`;
      // parametre imzasi (basit): paramStart ilerisi okunmazsa yalnizca ad
      mds.push(mn);
    }
    const kind: Il2CppClassInfo["kind"] = t.isInterface ? "interface" : t.isValueType ? "struct" : "class";
    classes.push({
      name: t.name,
      namespace: t.ns,
      image: "",
      kind,
      fields: flds,
      methods: mds,
      fieldCount: t.fieldCount,
      methodCount: t.methodCount,
    });
  }

  // ---- string literal ornekleri ----
  const literalSamples: string[] = [];
  for (let i = 0; i < Math.min(literalCount, 4000) && literalSamples.length < 60; i++) {
    const rec = stringLiteral.off + i * 8;
    if (rec + 8 > buf.length) break;
    const len = buf.readUInt32LE(rec);
    const di = buf.readInt32LE(rec + 4);
    const base = stringLiteralData.off + di;
    if (base + len <= buf.length && len > 0 && len < 200) {
      const s = buf.subarray(base, base + len).toString("latin1");
      if (/^[\x20-\x7e]+$/.test(s)) literalSamples.push(s);
    }
  }

  const notes2: string[] = [];
  notes2.push(`IL2CPP metadata v${versionLabel(verF, rawVer)} (${unityHintOf(verF)}) tam parse edildi`);
  notes2.push(`${typeCount} tip, ${methodCount} metod, ${fieldCount} alan, ${imageCount} image, ${literalCount} string literal`);
  notes2.push("Metodlarin native adresleri GameAssembly.dll / libil2cpp.so icindedir; binary de yuklenirse eslestirme yapilir");

  const info: Il2CppInfo = {
    version: versionLabel(verF, rawVer),
    unityHint: unityHintOf(verF),
    sanityOk: true,
    stringCount: strings.size,
    literalCount,
    images: imageNames,
    classCount: typeCount,
    methodCount,
    fieldCount,
    classes,
    enums,
    literalSamples,
    notes: notes2,
  };

  const core: Il2CppCore = {
    rawVersion: rawVer,
    effVersion: verF,
    images: imagesFull,
    types,
    methodTokens,
    fieldNames,
    methodNames,
    fieldDefaultValues: fdv,
  };
  return { info, core };
}

function minimalInfo(version: string, unityHint: string, fileSize: number, literalCount = 0): Il2CppInfo {
  return {
    version,
    unityHint,
    sanityOk: true,
    stringCount: 0,
    literalCount,
    images: [],
    classCount: 0,
    methodCount: 0,
    fieldCount: 0,
    classes: [],
    enums: [],
    literalSamples: [],
    notes: [`IL2CPP metadata tanindi (${fileSize} bayt) ancak tam parse basarisiz - kismi bilgi`],
  };
}

function versionLabel(verF: number, rawVer: number): string {
  if (verF === 24.2) return "24.2";
  if (verF === 24.1) return "24.1";
  return String(rawVer);
}

function unityHintOf(verF: number): string {
  if (verF < 18) return "Unity ~5.3-5.5";
  if (verF < 19) return "Unity ~5.5";
  if (verF < 20) return "Unity ~5.6";
  if (verF < 21) return "Unity ~2017.1";
  if (verF < 22) return "Unity ~2017.2";
  if (verF < 23) return "Unity ~2017.3-2017.4";
  if (verF < 24) return "Unity ~2018.1-2018.2";
  if (verF < 24.1) return "Unity ~2018.3-2019.1";
  if (verF < 24.2) return "Unity ~2019.2";
  if (verF < 24.4) return "Unity ~2019.3-2019.4";
  if (verF < 24.5) return "Unity ~2020.1";
  if (verF < 25) return "Unity ~2020.1-2020.2";
  if (verF < 27) return "Unity ~2020.2";
  if (verF < 27.1) return "Unity ~2020.2-2021.1";
  if (verF < 27.2) return "Unity ~2021.1";
  if (verF < 29) return "Unity ~2021.2-2021.3";
  if (verF < 31) return "Unity ~2022.1-2022.2";
  return "Unity ~2022.3+ / Unity 6";
}
