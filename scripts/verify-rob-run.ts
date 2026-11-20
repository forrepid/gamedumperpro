// ROB_RUN.exe derin analiz dogrulama scripti (ara-dev)
import fs from "node:fs";
import path from "node:path";

async function main(): Promise<void> {
  // Next.js olmayan sade ortam: dogrudan analiz modulunu cagir
  const { analyzeBuffer } = await import("../src/lib/analysis/index");

  const file = process.argv[2] ?? "/home/z/my-project/storage/uploads/a5930196-1534-4ac5-bf81-486c33fb1aec__ROB_RUN.exe";
  const buf = fs.readFileSync(file);
  const name = path.basename(file).replace(/^[0-9a-f-]+__/, "");

  const t0 = Date.now();
  const { result, report, sdkContents } = analyzeBuffer(buf, name);
  const ms = Date.now() - t0;

console.log("=== OZET ===");
console.log("kind:", result.kind, "| engine:", result.engine.detected, result.engine.version ?? "");
console.log("süre:", ms, "ms");
console.log("");
console.log("--- debug ---");
console.log("pdb:", result.pe?.debugPdb?.slice(0, 80));
console.log("pdb guid:", result.pe?.debug?.guid, "age:", result.pe?.debug?.pdb?.age);
console.log("debug entries:", result.pe?.debug?.entries.length, JSON.stringify(result.pe?.debug?.entries?.slice(0, 4)));
console.log("coff:", result.pe?.debug?.coffSymbols, "reproducible:", result.pe?.debug?.reproducible);
console.log("");
console.log("--- fonksiyonlar ---");
console.log("total:", result.functions?.total, "source:", result.functions?.source, "detailed:", result.functions?.detailed, "disassembled:", result.functions?.disassembled);
const first = result.functions?.functions.slice(0, 3) ?? [];
for (const f of first) console.log(`  #${f.idx} ${f.label ?? "sub_" + f.va.toString(16)} size=${f.size} apis=${f.apiCalls.length} strings=${f.strings.length} asm=${!!f.asm} pseudo=${!!f.pseudo}`);
const withPseudo = result.functions?.functions.find((f) => f.pseudo);
if (withPseudo?.pseudo) {
  console.log("");
  console.log("--- pseudo ornegi (ilk 18 satir) ---");
  console.log(withPseudo.pseudo.split("\n").slice(0, 18).join("\n"));
}
const withAsm = result.functions?.functions.find((f) => f.asm);
if (withAsm?.asm) {
  console.log("");
  console.log("--- asm ornegi (ilk 14 satir) ---");
  console.log(withAsm.asm.split("\n").slice(0, 14).join("\n"));
}
console.log("");
console.log("--- rtti ---");
console.log("available:", result.rtti?.available, "total:", result.rtti?.total, "classes:", result.rtti?.classes.length, "enums:", result.rtti?.enumNames.length);
console.log("");
console.log("--- structlar ---");
console.log("total:", result.structs?.total);
for (const s of result.structs?.structs.slice(0, 5) ?? []) {
  console.log(`  ${s.kind} ${s.name} [${s.source}] size~${s.size?.toString(16)} fields=${s.fields.length}`);
}
console.log("");
console.log("--- enumlar ---");
console.log("total:", result.enums?.total);
for (const e of result.enums?.enums.slice(0, 5) ?? []) console.log(`  ${e.name} [${e.source}] uye=${e.members.length}`);
console.log("");
console.log("--- kaynaklar ---");
console.log("total:", result.resources?.total, "versionInfo:", JSON.stringify(result.resources ? result.pe?.versionInfo : null)?.slice(0, 200));
console.log("");
console.log("--- SDK ---");
console.log("files:", sdkContents.map((f) => `${f.name}(${f.content.length}B)`).join(", "));
console.log("");
console.log("rapor uzunluk:", report.length, "satir:", report.split("\n").length);
console.log("");
console.log("notes:", result.notes.length, "errors:", result.errors);
for (const e of result.errors) console.log("  HATA:", e);
}

void main();
