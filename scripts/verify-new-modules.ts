// ----------------------------------------------------------------------------
// verify-new-modules.ts - yeni modullerin sentetik orneklerle dogrulamasi:
//   IL2CPP metadata + binary eslestirme, minidump + PE kurtarma, pak/utoc/
//   uasset/macho, memmap cihazi, hex/AOB/yama. Konsol raporu basar.
// ----------------------------------------------------------------------------

import fs from "node:fs";
import path from "node:path";

import { analyzeBuffer } from "../src/lib/analysis";
import { parseMemMapText, openRawWithMemmap, searchMemory, recoverModulePe } from "../src/lib/analysis/mem";
import { hexView, parseAobPattern, aobSearch, applyPatches } from "../src/lib/analysis/hex";

const DIR = path.join(process.cwd(), "research", "samples");

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    pass++;
    console.log(`  OK   ${name}${detail ? ` - ${detail}` : ""}`);
  } else {
    fail++;
    console.log(`  FAIL ${name}${detail ? ` - ${detail}` : ""}`);
  }
}

function load(n: string): Buffer {
  return fs.readFileSync(path.join(DIR, n));
}

// ---------------------------------------------------------------------------
// 1) IL2CPP metadata
// ---------------------------------------------------------------------------
console.log("\n=== IL2CPP metadata (global-metadata.dat v27) ===");
{
  const buf = load("global-metadata.dat");
  const a = analyzeBuffer(buf, "global-metadata.dat");
  check("kind=metadata", a.result.kind === "metadata", a.result.kind);
  check("il2cpp tespit", !!a.result.il2cpp && a.result.il2cpp.sanityOk, `v${a.result.il2cpp?.version}`);
  check("classCount>=6", (a.result.il2cpp?.classCount ?? 0) >= 6, String(a.result.il2cpp?.classCount));
  check("enum KeyCode bulundu", !!a.result.il2cpp?.enums.some((e) => e.name === "KeyCode"));
  const kc = a.result.il2cpp?.enums.find((e) => e.name === "KeyCode");
  check("enum degerleri 32/27", !!kc && kc.members.some((m) => m.name === "Space" && m.value === 32));
  check("images 3", (a.result.il2cpp?.images.length ?? 0) === 3, a.result.il2cpp?.images.join(","));
}

// ---------------------------------------------------------------------------
// 2) IL2CPP binary (tek basina)
// ---------------------------------------------------------------------------
console.log("\n=== IL2CPP binary (GameAssembly.dll tek basina) ===");
{
  const buf = load("GameAssembly.dll");
  const a = analyzeBuffer(buf, "GameAssembly.dll");
  check("kind=pe", a.result.kind === "pe");
  const bin = a.result.il2cppBin;
  check("il2cppBin detected", !!bin?.detected, bin?.reason);
  check("codeRegistration bulundu", !!bin?.codeRegistration, bin?.codeRegistration ? `RVA 0x${bin.codeRegistration.rva.toString(16)}` : "");
  check("codeGenModules count=3", bin?.codeGenModules?.count === 3, String(bin?.codeGenModules?.count));
  check("methodPointersResolved=7", bin?.methodPointersResolved === 7, String(bin?.methodPointersResolved));
  check("metadataRegistration yok (metadata bagli degil)", !bin?.metadataRegistration);
}

// ---------------------------------------------------------------------------
// 3) IL2CPP bagli eslestirme (metadata + binary) -> dump.cs + script.json
// ---------------------------------------------------------------------------
console.log("\n=== IL2CPP bagli eslestirme (metadata <-> binary) ===");
{
  const meta = load("global-metadata.dat");
  const bin = load("GameAssembly.dll");
  const a = analyzeBuffer(bin, "GameAssembly.dll", { il2cppMetadata: meta });
  const b = a.result.il2cppBin;
  check("linked=true", !!b?.linked);
  check("metadataRegistration bulundu", !!b?.metadataRegistration, b?.metadataRegistration ? `RVA 0x${b.metadataRegistration.rva.toString(16)}` : "");
  check("fieldOffsetsTypes>0", (b?.fieldOffsetsTypes ?? 0) > 0, String(b?.fieldOffsetsTypes));
  const dumpCs = a.sdkContents.find((c) => c.name === "dump.cs");
  const scriptJson = a.sdkContents.find((c) => c.name === "script.json");
  check("dump.cs uretildi", !!dumpCs, dumpCs ? `${dumpCs.content.length} B` : "");
  check("script.json uretildi", !!scriptJson);
  if (dumpCs) {
    check("dump.cs RVA satiri", /RVA: 0x[0-9A-F]+ Offset:/.test(dumpCs.content));
    check("dump.cs class Player", dumpCs.content.includes("class Player"));
    check("dump.cs parent MonoBehaviour", dumpCs.content.includes(": MonoBehaviour"));
    check("dump.cs field offset", dumpCs.content.includes("// 0x"));
  }
  if (scriptJson) {
    const s = JSON.parse(scriptJson.content) as { Methods: { Name: string; Rva: string }[] };
    check("script.json metodlar", s.Methods.length >= 7, String(s.Methods.length));
    check("script.json Assembly-CSharp adresli", s.Methods.some((m) => m.Name.includes("Assembly-CSharp.dll") && m.Rva !== "0x0"));
  }
}

// ---------------------------------------------------------------------------
// 4) minidump + PE kurtarma
// ---------------------------------------------------------------------------
console.log("\n=== minidump (process.dmp) + PE kurtarma ===");
{
  const buf = load("process.dmp");
  const a = analyzeBuffer(buf, "process.dmp");
  check("kind=minidump", a.result.kind === "minidump");
  const mem = a.result.mem;
  check("mem device", !!mem, mem?.device);
  check("arch x86_64", mem?.arch === "x86_64", mem?.arch);
  check("os Windows", (mem?.os ?? "").includes("Windows"), mem?.os);
  check("modul sayisi 1", mem?.moduleCount === 1, mem?.modules[0]?.name);
  check("modul kurtarilabilir", mem?.modules[0]?.recoverable === true, `%${mem?.modules[0]?.recoveredRangePct}`);
  check("bogeler >= 3", (mem?.regionCount ?? 0) >= 3, String(mem?.regionCount));

  // PE kurtarma + yeniden analiz
  const { parseMiniDump } = await import("../src/lib/analysis/mem");
  const md = parseMiniDump(buf);
  if (!md) throw new Error("minidump parse edilemedi");
  const base = md.modules[0].base;
  const notes: string[] = [];
  const rec = recoverModulePe(md.device, base, 0x2000, notes);
  check("PE kurtarma basarili", !!rec, notes.join("; "));
  if (rec) {
    const ra = analyzeBuffer(rec, "recovered.dll");
    check("kurtarilan PE parse", ra.result.kind === "pe", `sections=${ra.result.pe?.sections.length}`);
    check("kurtarilan PE fonksiyonlari", (ra.result.functions?.total ?? 0) >= 1, String(ra.result.functions?.total));
    check("kurtarilan PE string", ra.result.strings.some((s) => s.value.includes("DumperSample")));
  }
}

// ---------------------------------------------------------------------------
// 5) ortak oyun dosyalari
// ---------------------------------------------------------------------------
console.log("\n=== ortak oyun dosyalari (pak/utoc/uasset/macho) ===");
{
  const a = analyzeBuffer(load("test.pak"), "test.pak");
  check("pak kind", a.result.kind === "pak");
  const pak = a.result.gameFiles?.pak;
  check("pak v8", pak?.version === 8);
  check("pak mountPoint", pak?.mountPoint === "/Game/");
  check("pak 2 kayit isimli", pak?.namedEntries === 2, pak?.entries.map((e) => e.name).join(", "));
  check("pak comp methods", !!pak?.compressionMethods.includes("Oodle"));

  const b = analyzeBuffer(load("test.utoc"), "test.utoc");
  const utoc = b.result.gameFiles?.utoc;
  check("utoc v1 + 3 chunk", utoc?.entryCount === 3 && utoc.entries.length === 3);
  check("utoc comp Oodle", !!utoc?.compressionMethods.includes("Oodle"));
  check("utoc chunkType PackageData", utoc?.entries[0]?.chunkType === "PackageData");

  const c = analyzeBuffer(load("test.uasset"), "test.uasset");
  const ua = c.result.gameFiles?.uasset;
  check("uasset isimler", !!ua?.names.includes("PlayerStart"), ua?.names.join(","));
  check("uasset UE4 surum", ua?.ue4Version === 522);

  const d = analyzeBuffer(load("test.macho"), "test.macho");
  const mo = d.result.gameFiles?.macho;
  check("macho thin x86_64", mo?.format === "thin" && mo.archs[0]?.cpu === "x86_64");
  check("macho __TEXT segment", !!mo?.segments.some((s) => s.name === "__TEXT"));
  check("macho dylib libSystem", !!mo?.dylibs.some((x) => x.includes("libSystem")));
}

// ---------------------------------------------------------------------------
// 6) memmap cihazi + arama
// ---------------------------------------------------------------------------
console.log("\n=== memmap cihazi (LeechCore benzeri) ===");
{
  const raw = load("memory.bin");
  const mapText = fs.readFileSync(path.join(DIR, "memmap.txt"), "utf8");
  const entries = parseMemMapText(mapText);
  check("memmap 2 aralik", entries.length === 2, JSON.stringify(entries));
  const dev = openRawWithMemmap(raw, mapText);
  check("cihaz kuruldu", !!dev, `${dev?.ranges().length} aralik`);
  if (dev) {
    const read = dev.read(0x10, 18);
    check("VA okuma (remap)", !!read?.toString("latin1").startsWith("MEMMAP-TARGET"), read?.toString("latin1"));
    const pat = parseAobPattern("53 45 43 4f 4e 44"); // "SECOND"
    const hits = searchMemory(dev, pat.bytes);
    check("bellek arama SECOND", hits.length === 1 && hits[0].va === 0x20010, hits.map((h) => `0x${h.va.toString(16)}`).join(","));
  }
}

// ---------------------------------------------------------------------------
// 7) hex / AOB / yama
// ---------------------------------------------------------------------------
console.log("\n=== hex / AOB / yama ===");
{
  const bin = load("GameAssembly.dll");
  const view = hexView(bin, 0, 64);
  check("hex 4 satir", view.rows.length === 4);
  check("hex MZ", view.rows[0].hex[0] === "4d" && view.rows[0].ascii.startsWith("MZ"));

  // push rbp (0x55) ara
  const pat = parseAobPattern("55 48 89 E5");
  check("AOB desen parse", pat.bytes.length === 4 && !pat.error);
  const res = aobSearch(bin, pat.bytes, { limit: 16 });
  check("AOB >= 7 hit", res.matches.length >= 7, String(res.matches.length));

  const patched = applyPatches(bin, [{ off: 0, bytes: [0x90, 0x90], orig: [77, 90] }]);
  check("yama uygulandi", patched.applied === 1 && patched.buf[0] === 0x90 && patched.buf[1] === 0x90);
}

// ---------------------------------------------------------------------------
console.log(`\nSONUC: ${pass} OK, ${fail} FAIL`);
process.exit(fail > 0 ? 1 : 0);
