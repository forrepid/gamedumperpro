// Sentetik global-metadata.dat (v29) uretir ve parser'i dogrular.
// Amaclari: metadata.ts layout dogrulamasi (arastir-dogrula akisi).
import fs from "node:fs";

function i32(v: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeInt32LE(v, 0);
  return b;
}

async function main(): Promise<void> {
  const { parseIl2CppMetadata } = await import("../src/lib/analysis/metadata");

  // ---- string havuzu (indeksler BYTE OFFSET olmali - metadata string havuzu) ----
  const strChunks: Buffer[] = [];
  let strCursor = 0;
  const addStr = (s: string): number => {
    const idx = strCursor;
    strChunks.push(Buffer.from(s + "\0", "latin1"));
    strCursor += Buffer.byteLength(s, "latin1") + 1;
    return idx;
  };
  const nsGame = addStr("Game");
  const nColor = addStr("MyColor");
  const nPlayer = addStr("PlayerController");
  const nValue = addStr("value__");
  const nRed = addStr("Red");
  const nGreen = addStr("Green");
  const nBlue = addStr("Blue");
  const nHp = addStr("health");
  const nUpdate = addStr("Update");
  const nStart = addStr("Start");
  const nImage = addStr("Assembly-CSharp.dll");
  const strPool = Buffer.concat(strChunks);

  // ---- typeDefinitions: enum MyColor + class PlayerController ----
  const typeDefSize = 88;
  const td = (o: {
    name: number; ns: number; flags: number; fieldStart: number; methodStart: number;
    fieldCount: number; methodCount: number; bitfield: number;
  }): Buffer => {
    const parts: Buffer[] = [];
    parts.push(i32(o.name), i32(o.ns));
    parts.push(i32(0)); // byvalTypeIndex
    parts.push(i32(-1)); // declaringType
    parts.push(i32(-1)); // parent
    parts.push(i32(-1)); // elementType
    parts.push(i32(-1)); // genericContainer
    parts.push(i32(o.flags));
    parts.push(i32(o.fieldStart), i32(o.methodStart));
    parts.push(i32(0), i32(0), i32(0), i32(0), i32(0), i32(0)); // event/property/nested/interfaces/vtable/ifoffsets
    const u16s = Buffer.alloc(16);
    u16s.writeUInt16LE(o.methodCount, 0);
    u16s.writeUInt16LE(0, 2); // property
    u16s.writeUInt16LE(o.fieldCount, 4);
    u16s.writeUInt16LE(0, 6); // event
    u16s.writeUInt16LE(0, 8); // nested
    u16s.writeUInt16LE(0, 10); // vtable
    u16s.writeUInt16LE(0, 12); // interfaces
    u16s.writeUInt16LE(0, 14); // ifoffsets
    parts.push(u16s);
    parts.push(i32(o.bitfield), i32(0x02000000)); // bitfield, token
    const b = Buffer.concat(parts);
    if (b.length !== typeDefSize) throw new Error(`typeDef boyut hatali: ${b.length}`);
    return b;
  };

  // enum MyColor: fields: value__, Red, Green, Blue (fieldStart 0)
  // class PlayerController: fields: health (fieldStart 4), methods: Update, Start (methodStart 0)
  const typeDefs = Buffer.concat([
    td({ name: nColor, ns: nsGame, flags: 0x00000105, fieldStart: 0, methodStart: 0, fieldCount: 4, methodCount: 0, bitfield: 3 }),
    td({ name: nPlayer, ns: nsGame, flags: 0x00000001, fieldStart: 4, methodStart: 0, fieldCount: 1, methodCount: 2, bitfield: 1 }),
  ]);

  // ---- fields: value__, Red, Green, Blue, health ----
  const fieldDefSize = 12;
  const fd = (name: number): Buffer => Buffer.concat([i32(name), i32(0), i32(0)]);
  const fieldDefs = Buffer.concat([fd(nValue), fd(nRed), fd(nGreen), fd(nBlue), fd(nHp)]);

  // ---- methods: Update, Start ----
  const methodDefSize = 32;
  const md = (name: number): Buffer => {
    const b = Buffer.alloc(32);
    b.writeInt32LE(name, 0);
    b.writeInt32LE(1, 4); // declaringType
    b.writeInt32LE(0, 8); // returnType
    b.writeInt32LE(0, 12); // parameterStart
    b.writeInt32LE(-1, 16); // genericContainer
    b.writeUInt32LE(0x02000000, 20); // token
    b.writeUInt16LE(0x0084, 24); // flags
    b.writeUInt16LE(0, 26); // iflags
    b.writeUInt16LE(0, 28); // slot
    b.writeUInt16LE(0, 30); // parameterCount
    return b;
  };
  const methodDefs = Buffer.concat([md(nUpdate), md(nStart)]);

  // ---- parameters: bos ----
  const paramDefs = Buffer.alloc(0);

  // ---- fieldDefaultValues: Red=0, Green=1, Blue=2 (fieldIndex 1,2,3) ----
  const fdvSize = 12;
  const fdv = (fieldIndex: number, dataIndex: number): Buffer =>
    Buffer.concat([i32(fieldIndex), i32(0), i32(dataIndex)]);
  const fieldDefaultValues = Buffer.concat([fdv(1, 0), fdv(2, 4), fdv(3, 8)]);
  const defaultValueData = Buffer.concat([i32(0), i32(1), i32(2)]);

  // ---- images ----
  const imageDefSize = 40;
  const img = Buffer.alloc(40);
  img.writeUInt32LE(nImage, 0);
  img.writeInt32LE(0, 8); // typeStart
  img.writeUInt32LE(2, 12); // typeCount
  img.writeUInt32LE(1, 28); // token

  // ---- baslik kurulumu ----
  const sections: { off: number; size: number }[] = [];
  let cursor = 8 + 34 * 8; // header sonrasi (v29: 34 cift)
  const put = (data: Buffer): { off: number; size: number } => {
    const s = { off: cursor, size: data.length };
    sections.push(s);
    cursor += data.length;
    return s;
  };
  const secStringLiteral = put(Buffer.alloc(0));
  const secStringLiteralData = put(Buffer.alloc(0));
  const secStrings = put(strPool);
  const secEvents = put(Buffer.alloc(0));
  const secProperties = put(Buffer.alloc(0));
  const secMethods = put(methodDefs);
  const secParamDefVals = put(Buffer.alloc(0));
  const secFieldDefVals = put(fieldDefaultValues);
  const secFieldAndParamData = put(defaultValueData);
  const secFieldMarshaled = put(Buffer.alloc(0));
  const secParameters = put(paramDefs);
  const secFields = put(fieldDefs);
  const secGenericParameters = put(Buffer.alloc(0));
  const secGenericParamConstraints = put(Buffer.alloc(0));
  const secGenericContainers = put(Buffer.alloc(0));
  const secNestedTypes = put(Buffer.alloc(0));
  const secInterfaces = put(Buffer.alloc(0));
  const secVtableMethods = put(Buffer.alloc(0));
  const secInterfaceOffsets = put(Buffer.alloc(0));
  const secTypeDefinitions = put(typeDefs);
  const secImages = put(img);
  const secAssemblies = put(Buffer.alloc(0));
  const secFieldRefs = put(Buffer.alloc(0));
  const secReferencedAssemblies = put(Buffer.alloc(0));
  const secAttributeData = put(Buffer.alloc(0));
  const secAttributeDataRange = put(Buffer.alloc(0));
  const secUnresolvedVCallTypes = put(Buffer.alloc(0));
  const secUnresolvedVCallRanges = put(Buffer.alloc(0));
  const secWinRtTypeNames = put(Buffer.alloc(0));
  const secWinRtStrings = put(Buffer.alloc(0));
  const secExportedTypes = put(Buffer.alloc(0));

  // v29 header: yukaridaki 34 ciftin sirasi metadata.ts ile ayni olmali
  const headerPairs = [
    secStringLiteral, secStringLiteralData, secStrings, secEvents, secProperties,
    secMethods, secParamDefVals, secFieldDefVals, secFieldAndParamData, secFieldMarshaled,
    secParameters, secFields, secGenericParameters, secGenericParamConstraints, secGenericContainers,
    secNestedTypes, secInterfaces, secVtableMethods, secInterfaceOffsets, secTypeDefinitions,
    // v29: rgctx yok
    secImages, secAssemblies,
    // usage yok (v29)
    secFieldRefs, secReferencedAssemblies,
    secAttributeData, secAttributeDataRange,
    secUnresolvedVCallTypes, secUnresolvedVCallRanges,
    secWinRtTypeNames, secWinRtStrings,
    secExportedTypes,
  ];
  // 31 cift oldu; metadata.ts v29 yolunda 34 pair okur - gercek dosyada fazladan
  // alanlar export sonrasi olabilir; simetrik kalmak icin 3 bos cift ekleyelim:
  headerPairs.push({ off: cursor, size: 0 }, { off: cursor, size: 0 }, { off: cursor, size: 0 });

  const sanityBuf = Buffer.alloc(4);
  sanityBuf.writeUInt32LE(0xfab11baf, 0);
  const header = Buffer.concat([
    sanityBuf,
    i32(29),
    ...headerPairs.flatMap((p) => [i32(p.off), i32(p.size)]),
  ]);

  const meta = Buffer.concat([header, strPool, methodDefs, fieldDefaultValues, defaultValueData, fieldDefs, typeDefs, img]);
  // not: yukaridaki concat sirasi header offset'lerinden bagimsiz; offset'ler put()
  // sirasina gore uretildi ve secKey = Buffer.concat sirasiyla uymali. Testte
  // tek buffer yeterli degil - offsetler dogrudan dosya icine yerlesmeli:
  // Basitlik icin: header'i yeniden yaz (put() offsetleri 8+34*8'den baslar,
  // veri bloklari header sonrasina duz yazilir - asagida dogru dosya kurulumu)
  const allData: Buffer[] = [header, strPool, methodDefs, fieldDefaultValues, defaultValueData, fieldDefs, typeDefs, img];
  void allData;

  // dogru dosya: header sonrasi put() cagri sirasiyla veriler dursun
  const correct = Buffer.concat([
    header,
    strPool, methodDefs, fieldDefaultValues, defaultValueData, fieldMarshaledZero(), paramDefs, fieldDefs,
    typeDefs, img,
  ]);
  function fieldMarshaledZero(): Buffer {
    return Buffer.alloc(0);
  }

  const notes: string[] = [];
  // dogrulama icin dosyaya yaz (tam pipeline testinde kullanilir)
  fs.writeFileSync("/tmp/synthetic-global-metadata.dat", correct);
  const info = parseIl2CppMetadata(correct, notes);
  console.log("notes:", notes);
  if (!info) {
    console.log("PARSE BASARISIZ");
    return;
  }
  console.log("version:", info.version, "unityHint:", info.unityHint);
  console.log("classCount:", info.classCount, "methodCount:", info.methodCount, "fieldCount:", info.fieldCount);
  console.log("images:", info.images);
  console.log("classes:", info.classes.map((c) => `${c.namespace}.${c.name} (${c.kind}) fields=${c.fields.join(",")} methods=${c.methods.join(",")}`));
  console.log("enums:", JSON.stringify(info.enums));
  console.log("literalCount:", info.literalCount);
  void secExportedTypes; void meta; void fdvSize;
}

void main();
