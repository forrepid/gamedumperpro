// ----------------------------------------------------------------------------
// make-samples.ts - yeni modullerin dogrulamasi icin sentetik oyun dosyalari
// uretir (research/samples/ altina yazar). Bu bir unit test degildir; gercek
// format layoutlarinin TS parserlariyla eslesmesini dogrulayan uretim araci.
//
// Uretilenler:
//   1. global-metadata.dat (v27, tam header + images/typedefs/methods/fields)
//   2. GameAssembly.dll (sentetik PE64: CodeRegistration + MetadataRegistration
//      + codeGenModules - Il2CppDumper SectionHelper deseni birebir)
//   3. process.dmp (minidump: ModuleList + Memory64List + MemoryInfoList +
//      SystemInfo + Exception + bellekte PE gorunumlu modul)
//   4. test.pak (UE pak v8: footer + primary index + 2 kayit)
//   5. test.utoc (IoStore TOC v1 + 3 chunk)
//   6. test.uasset (PackageFileSummary + isim tablosu)
//   7. test.macho (thin x64: LC_SEGMENT_64 + LC_MAIN + LC_LOAD_DYLIB)
//   8. memmap.txt + memory.bin (LeechCore memmap:// eslemesi dogrulamasi)
// ----------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";

const OUT = path.join(process.cwd(), "research", "samples");
fs.mkdirSync(OUT, { recursive: true });

// ---------------------------------------------------------------------------
// yardimcilar
// ---------------------------------------------------------------------------

class BufWriter {
  private chunks: Buffer[] = [];
  private len = 0;
  u8(v: number): this { return this.buf(Buffer.from([v & 0xff])); }
  u32(v: number): this {
    const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0, 0); return this.buf(b);
  }
  i32(v: number): this {
    const b = Buffer.alloc(4); b.writeInt32LE(v | 0, 0); return this.buf(b);
  }
  u64(v: number | bigint): this {
    const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v) & 0xffffffffffffffffn, 0); return this.buf(b);
  }
  u16(v: number): this {
    const b = Buffer.alloc(2); b.writeUInt16LE(v & 0xffff, 0); return this.buf(b);
  }
  bytes(b: Buffer): this { return this.buf(b); }
  fill(n: number, v = 0): this { return this.buf(Buffer.alloc(n, v)); }
  cstr(s: string): this { return this.buf(Buffer.from(s + "\0", "latin1")); }
  private buf(b: Buffer): this { this.chunks.push(b); this.len += b.length; return this; }
  get length(): number { return this.len; }
  toBuffer(): Buffer { return Buffer.concat(this.chunks); }
}

const hex = (n: number): string => `0x${n.toString(16).toUpperCase()}`;

// ---------------------------------------------------------------------------
// 1) global-metadata.dat v27
// ---------------------------------------------------------------------------

function makeMetadata(): Buffer {
  // --- isim havuzu ---
  const strings = new BufWriter();
  const strOffsets: Record<string, number> = {};
  const putStr = (s: string): number => {
    if (!(s in strOffsets)) {
      strOffsets[s] = strings.length;
      strings.cstr(s);
    }
    return strOffsets[s];
  };
  const images = [
    { name: "mscorlib.dll", typeCount: 2 },
    { name: "Assembly-CSharp.dll", typeCount: 3 },
    { name: "UnityEngine.CoreModule.dll", typeCount: 1 },
  ];
  // typedef tanimlari: [name, ns, kind, fields[], methods[], parentTypedefIdx]
  const typedefs: {
    name: string; ns: string; isEnum: boolean; isValueType: boolean;
    fields: string[]; methods: string[]; parentTypeIdx: number; isInterface: boolean;
  }[] = [];
  typedefs.push({ name: "Object", ns: "System", isEnum: false, isValueType: false, fields: ["m_cachedPtr"], methods: ["Equals", "GetHashCode"], parentTypeIdx: -1, isInterface: false });
  typedefs.push({ name: "KeyCode", ns: "UnityEngine", isEnum: true, isValueType: true, fields: ["value__", "Space", "Escape"], methods: [], parentTypeIdx: -1, isInterface: false });
  typedefs.push({ name: "Player", ns: "", isEnum: false, isValueType: false, fields: ["health", "speed", "nickname"], methods: ["Update", "TakeDamage", "Shoot"], parentTypeIdx: 5, isInterface: false }); // parent = MonoBehaviour (type idx 5)
  typedefs.push({ name: "GameConfig", ns: "", isEnum: false, isValueType: true, fields: ["maxPlayers", "gravity"], methods: [], parentTypeIdx: -1, isInterface: false });
  typedefs.push({ name: "IMobileInput", ns: "", isEnum: false, isValueType: false, fields: [], methods: ["GetAxis"], parentTypeIdx: -1, isInterface: true });
  typedefs.push({ name: "MonoBehaviour", ns: "UnityEngine", isEnum: false, isValueType: false, fields: [], methods: ["Invoke"], parentTypeIdx: 0, isInterface: false });

  // image typedef araliklari: mscorlib: [0,2), Assembly-CSharp: [2,3), CoreModule: [5,1)
  const imageRanges: { start: number; count: number }[] = [
    { start: 0, count: 2 },
    { start: 2, count: 3 },
    { start: 5, count: 1 },
  ];

  // field/method dizilimi (global siralama)
  const allFields: string[] = [];
  const allMethods: string[] = [];
  const typedefMeta = typedefs.map((t) => {
    const fieldStart = allFields.length;
    for (const f of t.fields) allFields.push(f);
    const methodStart = allMethods.length;
    for (const m of t.methods) allMethods.push(m);
    return { ...t, fieldStart, methodStart };
  });
  const totalFields = allFields.length;
  const totalMethods = allMethods.length;

  // enum degerleri (fieldDefaultValues): KeyCode.Space=32, Escape=27
  const enumFdv: { fieldIdx: number; value: number }[] = [];
  const keycode = typedefMeta[1];
  enumFdv.push({ fieldIdx: keycode.fieldStart + 1, value: 32 });
  enumFdv.push({ fieldIdx: keycode.fieldStart + 2, value: 27 });

  // --- method tokenlari: image bazli 0x06000000 + (rid+1) ---
  // codeGenModule.methodPointers indeksi = rid (token & 0xFFFFFF - 1)
  // image metodlari image'in ilk typedef'inin methodStart'indan baslar.
  const methodTokens: number[] = new Array(totalMethods).fill(0);
  let ridCounter = 0;
  for (const ir of imageRanges) {
    let rid = 0;
    for (let ti = ir.start; ti < ir.start + ir.count; ti++) {
      const t = typedefMeta[ti];
      for (let k = 0; k < t.methods.length; k++) {
        methodTokens[t.methodStart + k] = 0x06000000 + (++rid);
      }
    }
    ridCounter = Math.max(ridCounter, rid);
  }

  // --- string havuzu (sec() cagrilarindan ONCE tum adlari kaydet!) ---
  for (const img of images) putStr(img.name);
  for (const t of typedefs) { putStr(t.name); putStr(t.ns); }
  for (const t of typedefs) for (const f of t.fields) putStr(f);
  for (const t of typedefs) for (const m of t.methods) putStr(m);

  // --- string literal ---
  const literalStrings = ["Player", "MainCamera", "Assets/Scenes/Level1.unity", "net_cfg_v1"];
  const literalData = new BufWriter();
  const literalRecords = new BufWriter();
  for (const s of literalStrings) {
    const dataOff = literalData.length;
    literalData.bytes(Buffer.from(s, "latin1"));
    literalRecords.u32(s.length).i32(dataOff);
  }

  // --- headerPairs (metadata.ts walk sirasi ile BIREBIR) ---
  // [stringLiteral, stringLiteralData, strings, events, properties, methods,
  //  parameterDefaultValues, fieldDefaultValues, fieldAndParamDefData,
  //  fieldMarshaledSizes, parameters, fields, genericParameters,
  //  genericParameterConstraints, genericContainers, nestedTypes, interfaces,
  //  vtableMethods, interfaceOffsets, typeDefinitions, images, assemblies,
  //  fieldRefs, referencedAssemblies, attributesInfo, attributeTypes,
  //  attributeData(v29+), unresolvedVCall, unresolvedVCallRanges,
  //  windowsRuntimeTypeNames, windowsRuntimeStrings(v27+), exportedTypeDefinitions]
  //Once data bolumlerini sirali duzen: header 8 + 2*(alanlar).
  // header boyutu: sanity(4) + version(4) + 31 pair x 8 = 256
  const headerSize = 8 + 31 * 8;

  // data bolumleri sirasi: literal, literalData, strings, events(0), properties(0),
  // methods, paramDefault(0), fieldDefault, fieldAndParamDefData, fieldMarshaled(0),
  // parameters, fields, generic(0), genericCons(0), genericCont(0), nested(0),
  // interfaces(0), vtable(0), interfaceOffsets(0), typeDefinitions, images,
  // assemblies, fieldRefs(0), referencedAssemblies(0), attributesInfo(0),
  // attributeTypes(0), unresolvedVCall(0), ranges(0), winRTNames(0),
  // winRTStrings(0), exported(0)

  let cursor = headerSize;
  const sec = (size: number): { off: number; size: number } => {
    const o = cursor; cursor += size; return { off: o, size };
  };
  const secEmpty = (): { off: number; size: number } => ({ off: 0, size: 0 });

  const stringLiteral = sec(literalRecords.length);
  const stringLiteralData = sec(literalData.length);
  const stringsSec = sec(strings.length);
  secEmpty(); // events
  secEmpty(); // properties
  const methodsSec = sec(totalMethods * 32);
  secEmpty(); // parameterDefaultValues
  const fdvSec = sec(enumFdv.length * 12);
  const fieldDefData = sec(8);
  secEmpty(); // fieldMarshaledSizes
  const parametersSec = sec(0);
  const fieldsSec = sec(totalFields * 12);
  secEmpty(); secEmpty(); secEmpty(); secEmpty(); secEmpty(); secEmpty(); secEmpty(); // generic..interfaceOffsets
  const typeDefinitionsSec = sec(typedefMeta.length * 88);
  const imagesSec = sec(images.length * 40);
  const assembliesSec = sec(images.length * 40);
  secEmpty(); secEmpty(); // fieldRefs, referencedAssemblies
  secEmpty(); secEmpty(); // attributesInfo, attributeTypes
  secEmpty(); secEmpty(); // unresolvedVCallTypes, Ranges
  secEmpty(); // windowsRuntimeTypeNames
  secEmpty(); // windowsRuntimeStrings
  secEmpty(); // exportedTypeDefinitions

  // --- body'i yaz ---
  const body = new BufWriter();
  void body;
  const totalSize = cursor;
  const out = Buffer.alloc(totalSize);

  // header
  out.writeUInt32LE(0xfab11baf, 0);
  out.writeInt32LE(27, 4);
  let hpos = 8;
  const writePair = (s: { off: number; size: number }): void => {
    out.writeUInt32LE(s.off, hpos); out.writeInt32LE(s.size, hpos + 4); hpos += 8;
  };
  // 31 pair (metadata.ts v27 walk sirasi ile birebir):
  // literal, literalData, strings, events, properties, methods, paramDefault,
  // fdv, fieldDefData, fieldMarshaled, parameters, fields, genericParams,
  // genericCons, genericCont, nested, interfaces, vtable, interfaceOffsets,
  // typeDefinitions, images, assemblies, fieldRefs, refAsm, attrInfo, attrTypes,
  // unresolvedTypes, unresolvedRanges, winRTNames, winRTStrings, exported
  const E = secEmpty;
  writePair(stringLiteral); writePair(stringLiteralData); writePair(stringsSec);
  writePair(E()); writePair(E()); // events, properties
  writePair(methodsSec); writePair(E()); writePair(fdvSec); // paramDefault
  writePair(fieldDefData); writePair(E()); writePair(parametersSec); // fieldMarshaled
  writePair(fieldsSec); writePair(E()); writePair(E()); // genericParams, genericCons
  writePair(E()); writePair(E()); writePair(E()); // genericCont, nested, interfaces
  writePair(E()); writePair(E()); // vtable, interfaceOffsets
  writePair(typeDefinitionsSec); writePair(imagesSec); writePair(assembliesSec);
  writePair(E()); // fieldRefs
  writePair(E()); // referencedAssemblies
  writePair(E()); writePair(E()); // attributesInfo, attributeTypes
  writePair(E()); writePair(E()); // unresolvedVCallTypes, Ranges
  writePair(E()); // windowsRuntimeTypeNames
  writePair(E()); // windowsRuntimeStrings
  writePair(E()); // exportedTypeDefinitions
  if (hpos !== headerSize) throw new Error(`header boyut eslesmedi: ${hpos} != ${headerSize}`);

  // literal + data + strings
  literalRecords.toBuffer().copy(out, stringLiteral.off);
  literalData.toBuffer().copy(out, stringLiteralData.off);
  strings.toBuffer().copy(out, stringsSec.off);

  // methods (v27 32B: name,declType,retType,paramStart,genericContainer,token, flags u16,iflags u16,slot u16,paramCount u16)
  for (let i = 0; i < totalMethods; i++) {
    const rec = methodsSec.off + i * 32;
    out.writeUInt32LE(putStr(allMethods[i]), rec);
    out.writeInt32LE(0, rec + 4); // declaringType (dogruya gerek yok; il2cpp typedef.methodStart ile eslesiyor)
    out.writeInt32LE(0, rec + 8); // returnType
    out.writeInt32LE(0, rec + 12); // parameterStart
    out.writeInt32LE(-1, rec + 16); // genericContainerIndex
    out.writeUInt32LE(methodTokens[i], rec + 20); // token
    out.writeUInt16LE(0, rec + 24); // flags
    out.writeUInt16LE(0, rec + 26); // iflags
    out.writeUInt16LE(0xffff, rec + 28); // slot
    out.writeUInt16LE(0, rec + 30); // parameterCount
  }

  // fieldDefaultValues (12B: fieldIndex, typeIndex, dataIndex)
  enumFdv.forEach((e, i) => {
    const rec = fdvSec.off + i * 12;
    out.writeInt32LE(e.fieldIdx, rec);
    out.writeInt32LE(8, rec + 4); // typeIndex = I4
    out.writeInt32LE(i * 4, rec + 8); // dataIndex
  });
  // fieldAndParamDefData: enum degerleri int32
  enumFdv.forEach((e, i) => out.writeInt32LE(e.value, fieldDefData.off + i * 4));

  // parameters (bos) + fields (12B: nameIndex, typeIndex, customAttributeIndex)
  for (let i = 0; i < totalFields; i++) {
    const rec = fieldsSec.off + i * 12;
    out.writeUInt32LE(putStr(allFields[i]), rec);
    out.writeInt32LE(6, rec + 4); // typeIndex (dummy)
    out.writeInt32LE(-1, rec + 8);
  }

  // typeDefinitions (v27 88B)
  for (let i = 0; i < typedefMeta.length; i++) {
    const t = typedefMeta[i];
    const rec = typeDefinitionsSec.off + i * 88;
    let p = rec;
    out.writeUInt32LE(putStr(t.name), p); p += 4; // nameIndex
    out.writeUInt32LE(putStr(t.ns), p); p += 4; // namespaceIndex
    out.writeInt32LE(0, p); p += 4; // byvalTypeIndex
    out.writeInt32LE(-1, p); p += 4; // declaringTypeIndex
    out.writeInt32LE(t.parentTypeIdx, p); p += 4; // parentIndex (il2cpp type idx testi icin typedef idx yazilir)
    out.writeInt32LE(-1, p); p += 4; // elementTypeIndex
    out.writeInt32LE(-1, p); p += 4; // genericContainerIndex
    out.writeUInt32LE(t.isInterface ? 0x20 : 0, p); p += 4; // flags
    out.writeInt32LE(t.fieldStart, p); p += 4;
    out.writeInt32LE(t.methodStart, p); p += 4;
    for (let k = 0; k < 6; k++) { out.writeInt32LE(0, p); p += 4; } // event/property/nested/interfaces/vtable/interfaceOffsets
    out.writeUInt16LE(t.methods.length, p); p += 2; // method_count
    out.writeUInt16LE(0, p); p += 2; // property_count
    out.writeUInt16LE(t.fields.length, p); p += 2; // field_count
    out.writeUInt16LE(0, p); p += 2; // event_count
    out.writeUInt16LE(0, p); p += 2; // nested_type_count
    out.writeUInt16LE(0, p); p += 2; // vtable_count
    out.writeUInt16LE(0, p); p += 2; // interfaces_count
    out.writeUInt16LE(0, p); p += 2; // interface_offsets_count
    const bitfield = (t.isValueType ? 1 : 0) | (t.isEnum ? 2 : 0);
    out.writeUInt32LE(bitfield, p); p += 4;
    out.writeUInt32LE(0x02000000 + i, p); p += 4; // token
    if (p !== rec + 88) throw new Error(`typedef ${i} boyut: ${p - rec}`);
  }

  // images (v24.1+ 40B: name, assembly, typeStart, typeCount, exportedTypeStart, exportedTypeCount, entryPoint, token, customAttrStart, customAttrCount)
  images.forEach((img, i) => {
    const rec = imagesSec.off + i * 40;
    out.writeUInt32LE(putStr(img.name), rec);
    out.writeInt32LE(i, rec + 4);
    out.writeInt32LE(imageRanges[i].start, rec + 8);
    out.writeUInt32LE(imageRanges[i].count, rec + 12);
    out.writeInt32LE(0, rec + 16);
    out.writeUInt32LE(0, rec + 20);
    out.writeInt32LE(0, rec + 24);
    out.writeUInt32LE(1, rec + 28); // token (v24.0->24.1 tespiti icin !=1 gereken yerde kullanilir; v27'de onemsiz)
    out.writeInt32LE(0, rec + 32);
    out.writeUInt32LE(0, rec + 36);
  });
  // assemblies (40B, parse edilmiyor)
  for (let i = 0; i < images.length; i++) out.writeUInt32LE(i, assembliesSec.off + i * 40);

  fs.writeFileSync(path.join(OUT, "global-metadata.dat"), out);
  console.log(`[1] global-metadata.dat: ${out.length} B, ${typedefMeta.length} typedef, ${totalMethods} metod, ${images.length} image`);
  return out;
}

// ---------------------------------------------------------------------------
// 2) GameAssembly.dll sentetik PE64
// ---------------------------------------------------------------------------

interface VaRef { va: number; off: number }

function makeGameAssembly(meta: Buffer): Buffer {
  // plan: .text 0x2000 (fonksiyonlar), .rdata 0x2000 (modul adlari + isaretciler),
  // .data 0x3000 (CodeGenModule structs + arrays + CR + MR + fieldOffsets + types + typeDefSizes)
  const imageBase = 0x180000000;
  const fileAlign = 0x200;
  const secRva = { text: 0x1000, rdata: 0x3000, data: 0x5000 };
  const secSizes = { text: 0x2000, rdata: 0x2000, data: 0x3000 };

  // .text: her metoda 16B pseudo-fonksiyon (push rbp; ...; ret)
  const totalMethods = 7; // mscorlib 2 + Assembly-CSharp 4 + CoreModule 1
  const textBuf = Buffer.alloc(secSizes.text);
  const fnVas: number[] = [];
  for (let i = 0; i < totalMethods; i++) {
    const off = i * 16;
    textBuf[off] = 0x55; // push rbp
    textBuf[off + 1] = 0x48; textBuf[off + 2] = 0x89; textBuf[off + 3] = 0xe5; // mov rbp,rsp
    textBuf[off + 4] = 0x5d; // pop rbp
    textBuf[off + 5] = 0xc3; // ret
    fnVas.push(imageBase + secRva.text + off);
  }

  // modul ismi + method pointer dizileri rdata'da
  const moduleNames = ["mscorlib.dll", "Assembly-CSharp.dll", "UnityEngine.CoreModule.dll"];
  const moduleMethodCounts = [2, 4, 1]; // Object:2, Player:3 + IMobileInput:1, MonoBehaviour:1
  const rdata = Buffer.alloc(secSizes.rdata);
  const data = Buffer.alloc(secSizes.data);
  let rd = 0x40; // isim stringleri
  const nameVas: number[] = [];
  for (const n of moduleNames) {
    Buffer.from(n + "\0", "latin1").copy(rdata, rd);
    nameVas.push(imageBase + secRva.rdata + rd);
    rd += n.length + 1;
  }
  // method pointer dizileri (rdata, 8B hizali)
  rd = (rd + 7) & ~7;
  const pointerArrayVas: number[] = [];
  const fnCursor = { i: 0 };
  for (let m = 0; m < 3; m++) {
    pointerArrayVas.push(imageBase + secRva.rdata + rd);
    for (let k = 0; k < moduleMethodCounts[m]; k++) {
      // metin bolumu adresi (pasif 0 yok)
      const va = fnVas[fnCursor.i++];
      rd = (rd + 7) & ~7;
      rdata.writeBigUInt64LE(BigInt(va), rd);
      rd += 8;
    }
  }
  void rd;

  // --- .data: CodeGenModule structs (v27 16 alan x8 = 128B), array, CR, MR ---
  const dVas = { base: imageBase + secRva.data };
  let d = 0x40;
  const writeQ = (v: number): number => { data.writeBigUInt64LE(BigInt(v) & 0xffffffffffffffffn, d); d += 8; return d - 8; };
  const writeI64 = (v: number): void => { data.writeBigInt64LE(BigInt(v), d); d += 8; };
  const alignD = (): void => { d = (d + 7) & ~7; };

  // CodeGenModule structs
  const moduleStructVas: number[] = [];
  for (let m = 0; m < 3; m++) {
    alignD();
    const structOff = d;
    moduleStructVas.push(imageBase + secRva.data + structOff);
    // 16 alan (v27): moduleName, cnt, mptr, adjCnt, adj, invokerIdx, revCnt, revIdx,
    // rgctxRCnt, rgctxR, rgctxCnt, rgctx, debuggerMeta, cacoGen, modInit, staticCtor,
    // metareg, codereg = 18?? -> v27 gercek: 16 alan (benim tablom)
    writeQ(nameVas[m]);           // moduleName
    writeI64(moduleMethodCounts[m]); // methodPointerCount
    writeQ(pointerArrayVas[m]);   // methodPointers
    for (let k = 3; k < 16; k++) writeQ(0); // diger alanlar 0
    void structOff;
  }
  alignD();
  // codeGenModules array
  const cgmArrayVa = imageBase + secRva.data + d;
  for (let m = 0; m < 3; m++) writeQ(moduleStructVas[m]);
  // CodeRegistration (v27): revCnt,revPtr,gmCnt,gmPtr,invCnt,invPtr,uvCnt,uvPtr,
  //                          interopCnt,interopPtr,wrCnt,wrPtr,cgmCnt,cgmPtr
  alignD();
  const crVa = imageBase + secRva.data + d;
  writeI64(4); writeQ(imageBase + secRva.rdata + 0x100); // reversePInvoke
  writeI64(8); writeQ(imageBase + secRva.rdata + 0x140); // genericMethodPointers
  writeI64(16); writeQ(imageBase + secRva.rdata + 0x180); // invokerPointers
  writeI64(4); writeQ(imageBase + secRva.rdata + 0x1c0); // unresolvedVirtualCall
  writeI64(2); writeQ(imageBase + secRva.rdata + 0x200); // interopData
  writeI64(0); writeQ(0); // windowsRuntimeFactory
  writeI64(3); writeQ(cgmArrayVa); // codeGenModulesCount + ptr
  const crBaseVa = crVa;
  void crBaseVa;

  // MetadataRegistration (v27, 16 alan) + destek dizileri.
  // Once diziler (adresleri gerekli), sonra {count, ptr} ciftleriyle struct.
  const typeDefCount = 6;
  const dVa = (off: number): number => imageBase + secRva.data + off;
  alignD();
  d = (d + 7) & ~7;
  // Il2CppType kayitlari (16B stride: data u64 + bits u32 + pad u32)
  const typesRecordsOff = d;
  for (let i = 0; i < typeDefCount; i++) {
    data.writeBigUInt64LE(BigInt(i), d); d += 8; // data = typedef index
    data.writeUInt32LE(0x00120000, d); d += 4; // bits: attrs 0, type 0x12 CLASS
    d += 4; // pad (16B stride)
  }
  // fieldOffsets kayitlari (her typedef icin u32 dizisi)
  const foRecordOffs: number[] = [];
  const typedefFieldCounts = [1, 3, 3, 2, 0, 0];
  for (let i = 0; i < typeDefCount; i++) {
    d = (d + 7) & ~7;
    foRecordOffs.push(d);
    const n = typedefFieldCounts[i];
    let off = 0x10 + i * 8;
    for (let k = 0; k < n; k++) { data.writeUInt32LE(off, d); off += i === 0 && k === 0 ? 8 : 4; d += 4; }
  }
  // typeDefinitionSizes (8B x typeDefCount)
  d = (d + 7) & ~7;
  const tdsOff = d;
  for (let i = 0; i < typeDefCount; i++) writeI64(0x40 + i * 8);
  // ptr dizileri
  d = (d + 7) & ~7;
  const typesArrayOff = d;
  for (let i = 0; i < typeDefCount; i++) writeQ(dVa(typesRecordsOff + i * 16));
  const foArrayOff = (d + 7) & ~7; d = foArrayOff;
  for (let i = 0; i < typeDefCount; i++) writeQ(dVa(foRecordOffs[i]));
  const tdsArrayOff = (d + 7) & ~7; d = tdsArrayOff;
  for (let i = 0; i < typeDefCount; i++) writeQ(dVa(tdsOff + i * 8));
  // MR struct: gcCnt,gc, giCnt,gi, gmtCnt,gmt, typesCnt,types, msCnt,ms,
  //            foCnt,fo, tdsCnt,tds, muCnt,mu
  const mrVa = imageBase + secRva.data + d;
  writeI64(4); writeQ(imageBase + secRva.rdata + 0x240);
  writeI64(4); writeQ(imageBase + secRva.rdata + 0x280);
  writeI64(4); writeQ(imageBase + secRva.rdata + 0x2c0);
  writeI64(typeDefCount); writeQ(dVa(typesArrayOff));
  writeI64(0); writeQ(0); // methodSpecs
  writeI64(typeDefCount); writeQ(dVa(foArrayOff));
  writeI64(typeDefCount); writeQ(dVa(tdsArrayOff));
  writeI64(0); writeQ(0); // metadataUsages
  const mrBaseVa = mrVa;
  void mrBaseVa;

  // --- PE dosya kurulumu ---
  const dos = Buffer.alloc(0x40);
  dos.write("MZ", 0, "latin1");
  dos.writeUInt32LE(0x40, 0x3c); // e_lfanew
  const nt = new BufWriter();
  nt.u32(0x00004550); // PE\0\0
  nt.u16(0x8664); // machine x64
  nt.u16(3); // NumberOfSections
  nt.u32(Math.floor(Date.now() / 1000)); // TimeDateStamp
  nt.u32(0); nt.u32(0); // PointerToSymbolTable, NumberOfSymbols (4+4!)
  nt.u16(240); // SizeOfOptionalHeader
  nt.u16(0x0022); // Characteristics: EXEC_IMAGE | DLL
  // OptionalHeader64 (alan sirasi: PE spec)
  nt.u16(0x20b); // magic
  nt.u8(14); nt.u8(0); // linker maj, min
  nt.u32(0x200); // SizeOfCode
  nt.u32(0x600); // SizeOfInitializedData
  nt.u32(0); // SizeOfUninitializedData
  nt.u32(secRva.text); // AddressOfEntryPoint (rva)
  nt.u32(secRva.text); // BaseOfCode
  // NOT: PE32+ icin BaseOfData ALANI YOK (PE32'de vardir) - optional header tam 240 B olmali
  nt.u64(imageBase); // ImageBase
  nt.u32(0x2000); // SectionAlignment
  nt.u32(0x200); // FileAlignment
  nt.u16(6); nt.u16(0); // OS maj, min
  nt.u16(0); nt.u16(0); // Image maj, min
  nt.u16(6); nt.u16(0); // Subsystem maj, min
  nt.u32(0); // Win32VersionValue
  nt.u32(0x8000); // SizeOfImage (section-aligned toplam)
  nt.u32(0x400); // SizeOfHeaders
  nt.u32(0); // CheckSum
  nt.u16(2); // Subsystem: GUI
  nt.u16(0x140); // DllCharacteristics
  nt.u64(0x100000); nt.u64(0x100000); // stack res, com
  nt.u64(0x100000); nt.u64(0x100000); // heap res, com
  nt.u32(0); nt.u32(16); // LoaderFlags, NumberOfRvaAndSizes
  nt.fill(16 * 8); // data directories bos
  const sections = new BufWriter();
  const mkSection = (name: string, vsz: number, va: number, rsz: number, raw: number, chars: number): void => {
    const b = Buffer.alloc(40);
    Buffer.from(name, "latin1").copy(b, 0);
    b.writeUInt32LE(vsz, 8); b.writeUInt32LE(va, 12);
    b.writeUInt32LE(rsz, 16); b.writeUInt32LE(raw, 20);
    b.writeUInt32LE(chars, 36);
    sections.bytes(b);
  };
  const fileOff = { text: 0x400, rdata: 0x400 + secSizes.text, data: 0x400 + secSizes.text + secSizes.rdata };
  mkSection(".text", secSizes.text, secRva.text, secSizes.text, fileOff.text, 0x60000020);
  mkSection(".rdata", secSizes.rdata, secRva.rdata, secSizes.rdata, fileOff.rdata, 0x40000040);
  mkSection(".data", secSizes.data, secRva.data, secSizes.data, fileOff.data, 0xc0000040);

  const header = Buffer.concat([dos, nt.toBuffer(), sections.toBuffer()]);
  const total = fileOff.data + secSizes.data;
  const out = Buffer.alloc(total);
  header.copy(out, 0);
  textBuf.copy(out, fileOff.text);
  rdata.copy(out, fileOff.rdata);
  data.copy(out, fileOff.data);

  fs.writeFileSync(path.join(OUT, "GameAssembly.dll"), out);
  console.log(`[2] GameAssembly.dll: ${out.length} B (imageBase ${hex(imageBase)}, CR ${hex(crVa - imageBase)} RVA, MR ${hex(mrVa - imageBase)} RVA)`);
  void meta;
  return out;
}

// ---------------------------------------------------------------------------
// 3) minidump + bellekte PE gorunumlu modul
// ---------------------------------------------------------------------------

function makeMiniDump(): Buffer {
  // --- modul PE'si (bellek gorunumlu: raw = virtual) ---
  const base = 0x7ff600000000;
  const sizeOfImage = 0x3000; // .text@0x1000 + .rdata@0x2000 -> toplam 0x3000
  const modulePe = Buffer.alloc(sizeOfImage);
  // DOS header
  modulePe.write("MZ", 0, "latin1");
  modulePe.writeUInt32LE(0x40, 0x3c);
  const ntOff = 0x40;
  modulePe.writeUInt32LE(0x00004550, ntOff);
  modulePe.writeUInt16LE(0x8664, ntOff + 4);
  modulePe.writeUInt16LE(2, ntOff + 6); // 2 bolum: .text + .rdata
  modulePe.writeUInt16LE(240, ntOff + 20); // SizeOfOptionalHeader (COFF: sig@+4, alanti 16)
  modulePe.writeUInt16LE(0x2022, ntOff + 22); // Characteristics
  const optOff = ntOff + 24;
  modulePe.writeUInt16LE(0x20b, optOff);
  modulePe.writeUInt32LE(0x1000, optOff + 16); // AddressOfEntryPoint rva
  modulePe.writeBigUInt64LE(BigInt(base), optOff + 24); // ImageBase
  modulePe.writeUInt32LE(0x1000, optOff + 32); // SectionAlignment
  modulePe.writeUInt32LE(0x1000, optOff + 36); // FileAlignment
  modulePe.writeUInt16LE(2, optOff + 68); // Subsystem GUI
  modulePe.writeUInt32LE(sizeOfImage, optOff + 56); // SizeOfImage
  modulePe.writeUInt32LE(0x1000, optOff + 60); // SizeOfHeaders
  const sectOff = optOff + 240;
  const sect1 = Buffer.alloc(40);
  Buffer.from(".text", "latin1").copy(sect1, 0);
  sect1.writeUInt32LE(0x1000, 8); // VirtualSize
  sect1.writeUInt32LE(0x1000, 12); // VirtualAddress
  sect1.writeUInt32LE(0x1000, 16); // SizeOfRawData
  sect1.writeUInt32LE(0x1000, 20); // PointerToRawData (bellek gorunumlu)
  sect1.writeUInt32LE(0x60000020, 36);
  sect1.copy(modulePe, sectOff);
  const sect2 = Buffer.alloc(40);
  Buffer.from(".rdata", "latin1").copy(sect2, 0);
  sect2.writeUInt32LE(0x1000, 8);
  sect2.writeUInt32LE(0x2000, 12);
  sect2.writeUInt32LE(0x1000, 16);
  sect2.writeUInt32LE(0x2000, 20);
  sect2.writeUInt32LE(0x40000040, 36);
  sect2.copy(modulePe, sectOff + 40);
  // bolum verisi: ret'ler + string + fonksiyon benzeri blok (fonksiyon taramasi icin)
  modulePe[0x1000] = 0x55; // push rbp
  modulePe[0x1001] = 0x48; modulePe[0x1002] = 0x89; modulePe[0x1003] = 0xe5;
  modulePe[0x1004] = 0x5d; modulePe[0x1005] = 0xc3; // pop rbp; ret
  modulePe[0x1010] = 0xc3;
  Buffer.from("DumperSample\x00", "latin1").copy(modulePe, 0x2080);

  // --- stack ornigi ---
  const stackVa = 0xef12340000;
  const stackData = Buffer.alloc(0x2000, 0xab);

  // dump araliklari: [base, base+sizeOfImage), [stackVa, +0x2000)
  const memRanges = [
    { start: base, size: sizeOfImage, data: modulePe },
    { start: stackVa, size: 0x2000, data: stackData },
  ];

  // --- akislar ---
  const streams: { type: number; data: Buffer }[] = [];

  // ModuleList
  const moduleName = "SampleGame.exe";
  const nameStr = new BufWriter();
  nameStr.u32((moduleName.length + 1) * 2);
  for (const ch of moduleName + "\0") nameStr.u16(ch.charCodeAt(0));
  const mod = new BufWriter();
  mod.u32(1); // NumberOfModules
  mod.u64(base); // BaseOfImage
  mod.u32(sizeOfImage); // SizeOfImage
  mod.u32(0); // CheckSum
  mod.u32(Math.floor(Date.now() / 1000)); // TimeDateStamp
  // ModuleNameRva: akis icindeki name offset (sonradan duzeltilir)
  const namePlaceholder = 28; // 4 + 24 = name RVA placeholder pozisyonu
  mod.u32(namePlaceholder);
  mod.fill(52); // VS_FIXEDFILEINFO
  mod.u64(0); mod.u64(0); // CvRecord, MiscRecord
  mod.u64(0); mod.u64(0); // Reserved
  // name'i kendi icine yerlestir: RVA = mod akisi icinde name'in offseti
  // mod akisi: 4 + 24 = 28 -> name burada
  const modBuf = mod.toBuffer();
  const nameBuf = nameStr.toBuffer();
  modBuf.writeUInt32LE(28, namePlaceholder - 4 + 0); // ModuleNameRva alanina 28 yaz (name offseti akis icinde 28)
  const moduleList = Buffer.concat([modBuf, nameBuf]);
  streams.push({ type: 4, data: moduleList });

  // Memory64List (BaseRva MUTLAKTIR: dosya basina gore)
  const memRangesData = Buffer.concat(memRanges.map((r) => r.data));
  const descSize = memRanges.length * 16;
  // akis sirasi: [0]=ModuleList, [1]=Memory64List -> mem64 RVA = bodyStart + moduleList boyu
  const mem64Rva = 32 + 5 * 12 + streams[0].data.length;
  const baseRvaValue = mem64Rva + 16 + descSize;
  const mem64b = new BufWriter();
  mem64b.u64(memRanges.length);
  mem64b.u64(baseRvaValue);
  for (const r of memRanges) mem64b.u64(r.start).u64(r.size);
  const mem64Data = Buffer.concat([mem64b.toBuffer(), memRangesData]);
  streams.push({ type: 9, data: mem64Data });

  // MemoryInfoList: 3 bolge (image commit, stack commit, free)
  const miHeader = new BufWriter();
  miHeader.u32(16); // SizeOfHeader
  miHeader.u32(48); // SizeOfEntry
  miHeader.u64(3); // NumberOfEntries
  const e1 = new BufWriter();
  const entry = (bAddr: number, rSize: number, state: number, prot: number, mtype: number): BufWriter => {
    const e = new BufWriter();
    e.u64(bAddr); e.u64(bAddr); e.u32(0x1000); e.u32(0);
    e.u64(rSize); e.u32(state); e.u32(prot); e.u32(mtype); e.u32(0);
    return e;
  };
  const e1b = entry(base, sizeOfImage, 0x1000, 0x20, 0x1000000); // MEM_IMAGE r-x
  const e2b = entry(stackVa, 0x2000, 0x1000, 0x04, 0x20000); // MEM_PRIVATE rw-
  const e3b = entry(0x7ff000000000, 0x10000, 0x20000, 0x01, 0); // MEM_RESERVE
  const miData = Buffer.concat([miHeader.toBuffer(), e1b.toBuffer(), e2b.toBuffer(), e3b.toBuffer()]);
  streams.push({ type: 16, data: miData });

  // SystemInfo
  const si = new BufWriter();
  si.u16(9); si.u16(6); si.u16(0xf00c); si.u16(8); si.u16(1); // arch x86_64
  si.u32(10); si.u32(0); si.u32(19045); si.u32(2); // Win 10.0.19045 NT
  si.u32(0); si.u16(0); si.u16(0);
  streams.push({ type: 7, data: si.toBuffer() });

  // Exception
  const ex = new BufWriter();
  ex.u32(0x1234); ex.u32(0); // ThreadId, alignment
  ex.u32(0xc0000005); ex.u32(0); // ExceptionCode ACCESS_VIOLATION, flags
  ex.u64(0); ex.u64(base + 0x1000); // record, address
  ex.u32(2); ex.u32(0); // numParams
  ex.u64(0); ex.u64(0); // params (15 slot; 2 yeter, kalan bos)
  for (let i = 0; i < 13; i++) ex.u64(0);
  ex.u32(0); ex.u32(0); // ThreadContext DataSize, Rva
  streams.push({ type: 6, data: ex.toBuffer() });

  // directory + body
  const dirCount = streams.length;
  const dirRva = 32;
  const bodyStart = dirRva + dirCount * 12;
  let cur = bodyStart;
  const dirEntries: Buffer[] = [];
  const bodies: Buffer[] = [];
  for (const s of streams) {
    dirEntries.push(
      (() => {
        const b = new BufWriter();
        b.u32(s.type).u32(s.data.length).u32(cur);
        return b.toBuffer();
      })(),
    );
    bodies.push(s.data);
    cur += s.data.length;
  }
  // header'daki NumberOfStreams'i duzelt
  const header = new BufWriter();
  header.u32(0x504d444d);
  header.u32(0x4a150000);
  header.u32(dirCount);
  header.u32(dirRva);
  header.u32(0);
  header.u32(Math.floor(Date.now() / 1000));
  header.u64(0n); // flags
  const headerBuf = header.toBuffer();
  const dump = Buffer.concat([headerBuf, ...dirEntries, ...bodies]);
  // moduleList icindeki name RVA mutlakti olmali (dump icinde): moduleList baslangici bodyStart'ta.
  // Bunu dogru yapmak icin yeniden hesapla:
  // (basitlik icin: moduleList 1. akis -> RVA = bodyStart; name offset = bodyStart + 28)
  const moduleListRva = bodyStart;
  dump.writeUInt32LE(moduleListRva + 28, moduleListRva + 24); // ModuleNameRva alanini mutlak yap
  fs.writeFileSync(path.join(OUT, "process.dmp"), dump);
  console.log(`[3] process.dmp: ${dump.length} B (modul base ${hex(base)}, stack ${hex(stackVa)})`);
  void stackVa;
  return dump;
}

// ---------------------------------------------------------------------------
// 4) pak v8
// ---------------------------------------------------------------------------

function makePak(): Buffer {
  const w = new BufWriter();
  // kayit verisi: 2 dosya
  const fileA = Buffer.from("HelloPakWorld. This is UE pak sample data.\x00", "latin1");
  const fileB = Buffer.alloc(128, 0x42);
  const indexStart = 0; // veri onceli; index sonda
  void indexStart;
  // index'i sonda tutacagiz: once data, sonra footer
  const dataAOff = 0x100;
  const dataBOff = dataAOff + fileA.length;
  // data
  w.fill(0x100); // header pad
  w.bytes(fileA);
  w.bytes(fileB);
  // primary index (v8: mountpoint FString, count, entries)
  const idxWriter = new BufWriter();
  const putFStr = (s: string): void => {
    idxWriter.i32(s.length + 1);
    idxWriter.cstr(s);
  };
  putFStr("/Game/");
  idxWriter.i32(2);
  const entryAOff = dataAOff;
  const entryBOff = dataBOff;
  // entry A
  putFStr("Sample/Config.ini");
  idxWriter.u64(entryAOff).u64(fileA.length);
  idxWriter.u32(0x1000); // compressionBlockSize (v<10)
  idxWriter.u32(0); // compression method index (None)
  idxWriter.fill(20, 0x1a); // hash
  // entry B
  putFStr("Sample/Data.bin");
  idxWriter.u64(entryBOff).u64(fileB.length);
  idxWriter.u32(0x1000);
  idxWriter.u32(0);
  idxWriter.fill(20, 0x2a);
  const idxBuf = idxWriter.toBuffer();
  const idxOff = w.length;
  w.bytes(idxBuf);
  // footer (v8): EncryptionKeyGuid yok (v9+), bEncryptedIndex 1B, Magic, Version,
  // IndexOffset, IndexSize, IndexHash 20B, CompressionMethods 5x32B
  const footer = new BufWriter();
  footer.u8(0); // bEncryptedIndex (v3+: magic'ten 1 once)
  footer.u32(0x5a6f12e1);
  footer.i32(8); // version
  footer.u64(idxOff).u64(idxBuf.length);
  footer.fill(20, 0x77);
  for (const name of ["None", "Zlib", "Gzip", "Oodle", "LZ4"]) {
    const b = Buffer.alloc(32);
    Buffer.from(name, "latin1").copy(b, 0);
    footer.bytes(b);
  }
  w.bytes(footer.toBuffer());
  const buf = w.toBuffer();
  fs.writeFileSync(path.join(OUT, "test.pak"), buf);
  console.log(`[4] test.pak: ${buf.length} B (index @${hex(idxOff)})`);
  return buf;
}

// ---------------------------------------------------------------------------
// 5) utoc + 6) uasset + 7) macho + 8) memmap
// ---------------------------------------------------------------------------

function makeUtoc(): void {
  const w = new BufWriter();
  w.bytes(Buffer.from("UTOC", "latin1")); // magic (null terminator YOK!)
  w.i32(1); // version
  const headerSize = 220;
  w.i32(headerSize); // TocHeaderSize
  w.i32(3); // TocEntryCount
  w.i32(0); // TocCompressedBlockEntryCount
  w.i32(0); // TocCompressedBlockEntrySize
  w.u32(0x10000000); // PartitionSize (u32!)
  w.i32(1); // PartitionCount
  w.i32(1); // CompressionMethodNameCount
  w.u32(0x10000); // CompressionBlockSize
  w.fill(220 - 40); // EncryptionKeyGuid + bEncryptedIndex + ContainerId + reserved
  // entries: ChunkId 12 (son byte = chunk type), Offset u32, Size u32
  for (let i = 0; i < 3; i++) {
    const b = Buffer.alloc(12);
    b.writeUInt32LE(0xaabbccdd, 0);
    b.writeUInt32LE(i, 4);
    b[11] = i === 0 ? 1 : 2; // PackageData / ContainerIndex
    w.bytes(b);
    w.u32(i * 0x20000); // offset
    w.u32(0x20000 - i * 0x100); // size
  }
  // compression name (32B)
  const name = Buffer.alloc(32);
  Buffer.from("Oodle", "latin1").copy(name, 0);
  w.bytes(name);
  const buf = w.toBuffer();
  fs.writeFileSync(path.join(OUT, "test.utoc"), buf);
  console.log(`[5] test.utoc: ${buf.length} B`);
}

function makeUasset(): void {
  const w = new BufWriter();
  w.u32(0x9e2a83c1);
  w.i32(-7); // LegacyFileVersion (UE4)
  w.i32(0); // LegacyUE3Version
  w.i32(522); // FileVersionUE4 (4.27)
  w.i32(0); // LicenseeVersion
  w.i32(0); // CustomVersions count
  w.i32(0x100); // TotalHeaderSize (dummy)
  // FolderName FString (ASCII)
  w.i32(12); w.cstr("/Game/Maps/");
  w.u32(0x08000000); // PackageFlags
  const nameTableOffPlaceholder = 0;
  w.i32(3); // NameCount
  w.i32(nameTableOffPlaceholder); // NameOffset placeholder
  w.i32(0); w.i32(0); // GatherableTextCount/Offset
  const nameTableOff = w.length;
  // name tablosu: i16 len + chars + \0
  for (const s of ["Level1", "StaticMesh", "PlayerStart"]) {
    w.u16(s.length + 1);
    w.cstr(s);
  }
  const buf = w.toBuffer();
  // nameOffset alan pozisyonu: nameCount@48..52, nameOffset@52..56
  buf.writeInt32LE(nameTableOff, 52);
  fs.writeFileSync(path.join(OUT, "test.uasset"), buf);
  console.log(`[6] test.uasset: ${buf.length} B (nameTable @${hex(nameTableOff)})`);
}

function makeMacho(): void {
  const w = new BufWriter();
  const buf32 = Buffer.alloc(4);
  // little-endian makina: 0xFEEDFACF -> diskte CE FA ED FE
  buf32.writeUInt32LE(0xcefaedfe, 0);
  w.bytes(buf32);
  w.u32(0x01000007); // cputype x86_64
  w.u32(3); // cpusub
  w.u32(6); // filetype MH_DYLIB
  w.u32(3); // ncmds: LC_SEGMENT_64, LC_MAIN, LC_LOAD_DYLIB
  w.u32(0); w.u32(0); // sizeofcmds, flags
  w.u32(0); // reserved (64-bit header = 32 B)
  // LC_SEGMENT_64 (__TEXT) - sabit 16B isim alanlari
  const seg = new BufWriter();
  seg.u32(0x19).u32(72 + 80); // cmd, cmdsize (1 section)
  const segName = Buffer.alloc(16);
  Buffer.from("__TEXT", "latin1").copy(segName, 0);
  seg.bytes(segName);
  seg.u64(0).u64(0x4000).u64(0x2000).u64(0x2000); // vmaddr, vmsize, fileoff, filesize
  seg.u32(7).u32(5).u32(1).u32(0); // maxprot, initprot, nsects, flags
  // section: __text (sabit 16+16B isim alanlari)
  const secName = Buffer.alloc(16);
  Buffer.from("__text", "latin1").copy(secName, 0);
  seg.bytes(secName);
  const secSeg = Buffer.alloc(16);
  Buffer.from("__TEXT", "latin1").copy(secSeg, 0);
  seg.bytes(secSeg);
  seg.u64(0x1000).u64(0x1000); // addr, size
  seg.u32(0).u32(4); // offset, align
  seg.u32(0).u32(0).u32(0); // reloff, nreloc, flags
  seg.u32(0).u32(0); // reserved1, reserved2
  seg.u32(0); // reserved3 (section_64 = 80 B)
  w.bytes(seg.toBuffer());
  // LC_MAIN
  const main = new BufWriter();
  main.u32(0x80000028).u32(24).u64(0x1000).u64(0);
  w.bytes(main.toBuffer());
  // LC_LOAD_DYLIB
  const dy = new BufWriter();
  dy.u32(0xc).u32(51); // cmd + dylib struct + string (cmdsize gerçek boyut)
  dy.u32(24).u32(2).u32(1).u32(1);
  dy.cstr("/usr/lib/libSystem.B.dylib");
  w.bytes(dy.toBuffer());
  const buf = w.toBuffer();
  // sizeofcmds duzelt (parser o alani okumuyor; ncmds yeterli)
  fs.writeFileSync(path.join(OUT, "test.macho"), buf);
  console.log(`[7] test.macho: ${buf.length} B`);
}

function makeMemmap(): void {
  const raw = Buffer.alloc(0x8000);
  // eslenen bolge: VA 0x10000..0x11000 -> raw 0x0..0x1000
  Buffer.from("MEMMAP-TARGET-DATA\x00", "latin1").copy(raw, 0x10);
  Buffer.from("SECOND-REGION\x00", "latin1").copy(raw, 0x1010);
  fs.writeFileSync(path.join(OUT, "memory.bin"), raw);
  const map = [
    "# LeechCore memmap stili",
    "00000000-00001000 : module1",
    "00020000-00021000 -> 00001000",
  ].join("\n");
  fs.writeFileSync(path.join(OUT, "memmap.txt"), map);
  console.log("[8] memory.bin (32 KB) + memmap.txt (2 aralik)");
}

// ---------------------------------------------------------------------------
// calistir
// ---------------------------------------------------------------------------

const metadata = makeMetadata();
makeGameAssembly(metadata);
makeMiniDump();
makePak();
makeUtoc();
makeUasset();
makeMacho();
makeMemmap();
console.log(`\nOrnekler hazir: ${OUT}`);
