// ----------------------------------------------------------------------------
// DumperPro Online - imza (signature) aday tarayici
//
// DumperPro games.ini'deki desenler + yaygin bilinen GObjects/GNames desenleri.
// Statik analiz: eslesmeler RVA/VA'ya cevirilir ancak CALISTIRMA olmadan
// dogrulanamaz -> sonuc "aday" olarak raporlanir (canli modda Dogrulanir).
// ----------------------------------------------------------------------------

import type { PeSection, SigCandidate } from "./types";
import { getSectionRaw } from "./pe";

interface PatternDef {
  name: string;
  pattern: string;
  note: string;
}

const PATTERNS: PatternDef[] = [
  {
    name: "GObjects (GUObjectArray)",
    pattern: "48 8B 05 ?? ?? ?? ?? 48 8D 54 24 ?? E8",
    note: "mov rax,[rip+disp32] -> disp32 RIPOUC referansindaki adres adaydir",
  },
  {
    name: "GObjects (zincir)",
    pattern: "48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8",
    note: "GUObjectArray okuyup FName duzeyinde cagri yapilan klasik uretim deseni",
  },
  {
    name: "GNames (FNamePool UE5)",
    pattern: "4C 8D 35 ?? ?? ?? ?? EB 16",
    note: "lea r14,[rip+disp32] + kisa atlama; FNamePool init komsulugu",
  },
  {
    name: "GNames (FNamePool UE5 v2)",
    pattern: "48 8D 35 ?? ?? ?? ?? EB 16",
    note: "lea rsi,[rip+disp32] varyanti (eski UE5/FNamePool baslangici)",
  },
  {
    name: "ProcessEvent (parmak izi)",
    pattern: "4C 8B DC 49 89 5B ?? 49 89 6B ?? 49 89 73 ?? 57 41 56 41 57 48 81 EC ?? ?? ?? ??",
    note: "UObject::ProcessEvent giris - vtable cozumculugu icin canli modda kullanilir",
  },
  {
    name: "PostRender (parmak izi)",
    pattern: "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30 48 8B F9 48 8B DA 48 8B 49 60",
    note: "UGameViewportClient::PostRender aday girisi",
  },
];

function matchWildcard(buf: Buffer, pattern: Buffer, mask: Buffer, from: number): number {
  // mask: 1 = literal, 0 = joker
  for (let i = from; i <= buf.length - pattern.length; i++) {
    let ok = true;
    for (let j = 0; j < pattern.length; j++) {
      if (mask[j] === 1 && buf[i + j] !== pattern[j]) { ok = false; break; }
    }
    if (ok) return i;
  }
  return -1;
}

function compilePattern(pat: string): { bytes: Buffer; mask: Buffer } {
  const tokens = pat.trim().split(/\s+/);
  const bytes: number[] = [];
  const mask: number[] = [];
  for (const t of tokens) {
    if (t === "??" || t === "?") { bytes.push(0); mask.push(0); }
    else { bytes.push(parseInt(t, 16)); mask.push(1); }
  }
  return { bytes: Buffer.from(bytes), mask: Buffer.from(mask) };
}

export function scanSignatureCandidates(
  buf: Buffer,
  sections: PeSection[],
  imageBase: number,
  maxHitsPerPattern = 5,
): SigCandidate[] {
  // taramayi kod + veri bolumleriyle sinirla (hiz)
  const scanTargets: { name: string; data: Buffer; rawPointer: number; va: number }[] = [];
  for (const s of sections) {
    if (s.rawSize === 0) continue;
    const data = getSectionRaw(buf, s);
    if (!data) continue;
    if (data.length > 96 * 1024 * 1024) continue;
    scanTargets.push({ name: s.name, data, rawPointer: s.rawPointer, va: s.virtualAddress });
  }
  if (scanTargets.length === 0) return [];

  const out: SigCandidate[] = [];
  for (const def of PATTERNS) {
    const { bytes, mask } = compilePattern(def.pattern);
    const hits: SigCandidate["hits"] = [];
    for (const target of scanTargets) {
      let from = 0;
      while (hits.length < maxHitsPerPattern) {
        const local = matchWildcard(target.data, bytes, mask, from);
        if (local === -1) break;
        const fileOffset = target.rawPointer + local;
        const rva = target.va + local;
        const va = imageBase + rva;
        hits.push({
          rva: `0x${rva.toString(16).toUpperCase()}`,
          va: `0x${va.toString(16).toUpperCase()}`,
          offset: `0x${fileOffset.toString(16).toUpperCase()}`,
        });
        from = local + 1;
        if (from > target.data.length - bytes.length) break;
      }
      if (hits.length >= maxHitsPerPattern) break;
    }
    out.push({
      name: def.name,
      pattern: def.pattern,
      hits,
      note: def.note,
    });
  }
  return out;
}
