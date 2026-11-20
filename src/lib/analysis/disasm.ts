// ----------------------------------------------------------------------------
// DumperPro Online - x86-64 cozucu + tahmini pseudo-C uretici (sifir bagimlilik)
//
// Kaynak/teyit: Intel SDM Vol.2 (Instruction Set Reference) + AMD64 APM Vol.3;
//     MSVC x64 kod uretimi kaliparlari (prologue/epilogue, RIP-relative,
//     REX on eki, ModRM/SIB/disp kodlamasi). Capstone/Zydis'ten bagimsiz,
//     yaygin komut alt kumesi cozulur; cozulemeyen bayt "db 0xXX" olur ve
//     tek bayt atlanir (kayma etkisi sinirli tutulur).
//
// ONEMLI NOTLAR (ONEMLI NOTLAR - bu modul icin):
//   1) Bu bir TAM disassembler DEGILDIR: AVX-512/VMX/SHA/ AES gibi nadir
//      aileler bilinmeyen olarak isaretlenir. Amaç statik decompile-öncesi
//      okunabilirlik; dogrulama canli modda yapilir.
//   2) Pseudo-C ciktisi TAHMINIDIR ("yaklasik"): register deger akisi tam
//      takip edilmez; yalnizca son bilinen kaynak (imm/string/IAT/vftable)
//      ile arguman ipuclari uretilir. Gercek decompiler (IDA/Hex-Rays)
//      degildir, iddia da edilmez.
//   3) Komut sozcugu icin ust sinir 15 bayt (x86 spec); asilan cocuklarin
//      kodlamasi db olarak yazilir.
//   4) Kullanim: yalnizca sahibi olunan/lisansli ikili dosyalarin offline
//      analizi. Cok oyunculu hile gelistirme kapsam disidir.
// ----------------------------------------------------------------------------

export interface AsmInsn {
  va: number; // hedef VA (imageBase + rva)
  size: number;
  text: string;
}

const R64 = [
  "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];
const R32 = [
  "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
  "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
];
const R16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"];
const R8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"];
const R8REX = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]; // REX yokken
const R8B = ["r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"];

const JCC8 = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"];
const JCC32 = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"];
const SETCC = ["seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta", "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg"];
const GRP1 = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const GRP2 = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"];
const GRP3 = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"];

interface Rex {
  present: boolean;
  w: boolean;
  r: boolean;
  x: boolean;
  b: boolean;
}

interface MemOperand {
  kind: "mem";
  base?: string;
  index?: string;
  scale?: number;
  disp: number;
  ripRel?: boolean; // disp32 = hedef VA
  ripTarget?: number;
}

interface RegOperand {
  kind: "reg";
  reg: string;
  width: number; // bayt
}

type Operand = RegOperand | MemOperand | { kind: "imm"; value: number; size: number } | { kind: "far"; text: string };

interface Decoded {
  va: number;
  size: number;
  mnem: string;
  ops: Operand[];
  width: number; // ana islenen genisligi (bayt)
  ok: boolean;
}

function regName(index: number, width: number, rex: Rex): string {
  // index zaten rex bitini icerir (decodeModrm tarafindan +8 eklendi)
  if (width === 8) return R64[index & 15];
  if (width === 4) return R32[index & 15];
  if (width === 2) return R16[index & 7];
  // 1 bayt: REX varsa yeni harita (spl/bpl/sil/dil), yoksa ah/ch/dh/bh
  if (rex.present) {
    return index < 8 ? R8[index] : R8B[index - 8];
  }
  return R8REX[index & 7];
}

function hex(n: number): string {
  const v = n < 0 ? -n : n;
  return (n < 0 ? "-0x" : "0x") + v.toString(16).toUpperCase();
}

function immSigned(v: number): number {
  return v | 0;
}

/** ModRM + SIB + disp cozumu. start: modrm baytinin offseti. */
function decodeModrm(
  buf: Buffer,
  start: number,
  end: number,
  width: number,
  rex: Rex,
  vaOf: (off: number) => number,
): { reg: RegOperand; rm: Operand; size: number } {
  const modrmByte = buf[start];
  const mod = (modrmByte >> 6) & 3;
  const regIdx = ((modrmByte >> 3) & 7) + (rex.r ? 8 : 0);
  const rmIdx = (modrmByte & 7) + (rex.b ? 8 : 0);
  let p = start + 1;

  const reg: RegOperand = { kind: "reg", reg: regName(regIdx, width, rex), width };

  if (mod === 3) {
    return { reg, rm: { kind: "reg", reg: regName(rmIdx, width, rex), width }, size: 1 };
  }

  let mem: MemOperand = { kind: "mem", disp: 0 };

  // RIP-goreli: mod=00, rm=101 (SIB'siz)
  if (mod === 0 && (modrmByte & 7) === 5) {
    if (p + 4 > end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: 5 };
    const disp = buf.readInt32LE(p);
    p += 4;
    const target = vaOf(p) + disp;
    mem = { kind: "mem", disp, ripRel: true, ripTarget: target };
    return { reg, rm: mem, size: p - start };
  }

  if ((modrmByte & 7) === 4) {
    // SIB bayti
    if (p >= end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: 2 };
    const sib = buf[p];
    p++;
    const scale = 1 << ((sib >> 6) & 3);
    const indexIdx = ((sib >> 3) & 7) + (rex.x ? 8 : 0);
    const baseIdx = (sib & 7) + (rex.b ? 8 : 0);
    const baseField = sib & 7;
    if (baseField === 5 && mod === 0) {
      // [scale*index + disp32]
      if (p + 4 > end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: p - start + 4 };
      const disp = buf.readInt32LE(p);
      p += 4;
      mem = { kind: "mem", disp, index: indexIdx === 4 ? undefined : regName(indexIdx, 8, rex), scale: indexIdx === 4 ? undefined : scale };
    } else {
      mem.base = regName(baseIdx, 8, rex);
      if (indexIdx !== 4) {
        mem.index = regName(indexIdx, 8, rex);
        mem.scale = scale;
      }
      if (mod === 1) {
        if (p + 1 > end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: p - start + 1 };
        mem.disp = buf.readInt8(p);
        p += 1;
      } else if (mod === 2) {
        if (p + 4 > end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: p - start + 4 };
        mem.disp = buf.readInt32LE(p);
        p += 4;
      }
    }
  } else {
    mem.base = regName(rmIdx, 8, rex);
    if (mod === 1) {
      if (p + 1 > end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: p - start + 1 };
      mem.disp = buf.readInt8(p);
      p += 1;
    } else if (mod === 2) {
      if (p + 4 > end) return { reg, rm: { kind: "imm", value: 0, size: 0 }, size: p - start + 4 };
      mem.disp = buf.readInt32LE(p);
      p += 4;
    }
  }

  return { reg, rm: mem, size: p - start };
}

function opText(o: Operand): string {
  switch (o.kind) {
    case "reg":
      return o.reg;
    case "imm":
      return hex(o.value);
    case "far":
      return o.text;
    case "mem": {
      let inner = "";
      if (o.ripRel && o.ripTarget !== undefined) {
        return `[${hex(o.ripTarget)}]`;
      }
      const parts: string[] = [];
      if (o.base) parts.push(o.base);
      if (o.index && o.scale) parts.push(`${o.index}*${o.scale}`);
      else if (o.index) parts.push(o.index);
      inner = parts.join("+");
      if (o.disp !== 0 || parts.length === 0) {
        inner = parts.length ? `${inner}${o.disp < 0 ? hex(o.disp) : "+" + hex(o.disp)}` : hex(o.disp);
      }
      return `[${inner}]`;
    }
  }
}

/** Bir komutu cozer. Basarisizsa ok=false (tek bayt db ile atlanir). */
function decodeAt(buf: Buffer, start: number, end: number, vaOf: (off: number) => number): Decoded {
  const va = vaOf(start);
  let p = start;

  const bad = (consume = 1): Decoded => ({ va, size: Math.min(consume, end - start), mnem: "db", ops: [{ kind: "imm", value: buf[p], size: 1 }], width: 0, ok: false });

  if (start >= end) return bad(1);

  // --- on ekler ---
  const rex: Rex = { present: false, w: false, r: false, x: false, b: false };
  let op66 = false;
  let repPrefix: 0 | 1 | 2 = 0; // 1=F2, 2=F3
  let segHint = "";
  for (let guard = 0; guard < 15; guard++) {
    if (p >= end) return bad(1);
    const b = buf[p];
    if (b === 0x66) { op66 = true; p++; continue; }
    if (b === 0x67 || b === 0x2e || b === 0x36 || b === 0x3e || b === 0x26) { p++; continue; }
    if (b === 0x64) { segHint = "fs:"; p++; continue; }
    if (b === 0x65) { segHint = "gs:"; p++; continue; }
    if (b === 0xf2) { repPrefix = 1; p++; continue; }
    if (b === 0xf3) { repPrefix = 2; p++; continue; }
    if (b === 0xf0) { p++; continue; } // lock
    if (b >= 0x40 && b <= 0x4f) {
      rex.present = true;
      rex.w = (b & 8) !== 0;
      rex.r = (b & 4) !== 0;
      rex.x = (b & 2) !== 0;
      rex.b = (b & 1) !== 0;
      p++;
      continue;
    }
    break;
  }

  const main = buf[p];
  p++;

  // --- iki baytli (0x0F) ---
  if (main === 0x0f) {
    if (p >= end) return bad(2);
    const op2 = buf[p];
    p++;
    const w = rex.w ? 8 : op66 ? 2 : 4;

    if (op2 === 0x05) return fin("syscall", [], w);
    if (op2 === 0x0b) return fin("ud2", [], w);
    if (op2 === 0x1e && p < end && buf[p] === 0xfa) { p++; return fin("endbr64", [], w); }
    if (op2 === 0x1f) {
      const m = decodeModrm(buf, p, end, 4, rex, vaOf);
      return fin("nop", [m.rm], w, p - start + m.size);
    }
    if (op2 === 0xa2) return fin("cpuid", [], w);
    if (op2 === 0x77) return fin("emms", [], w);
    if (op2 >= 0x80 && op2 <= 0x8f) {
      if (p + 4 > end) return bad(2);
      const rel = buf.readInt32LE(p);
      p += 4;
      return fin(JCC32[op2 - 0x80], [{ kind: "imm", value: vaOf(p) + rel, size: 4 }], w);
    }
    if (op2 >= 0x90 && op2 <= 0x9f) {
      const m = decodeModrm(buf, p, end, 1, rex, vaOf);
      return fin(SETCC[op2 - 0x90], [m.rm], w, p - start + m.size);
    }
    if (op2 === 0xaf) {
      const m = decodeModrm(buf, p, end, w, rex, vaOf);
      return fin("imul", [m.reg, m.rm], w, p - start + m.size);
    }
    if (op2 === 0xb0 || op2 === 0xb1) {
      const m = decodeModrm(buf, p, end, op2 === 0xb0 ? 1 : w, rex, vaOf);
      return fin("cmpxchg", [m.rm, m.reg], op2 === 0xb0 ? 1 : w, p - start + m.size);
    }
    if (op2 === 0xb6 || op2 === 0xb7) {
      const m = decodeModrm(buf, p, end, op2 === 0xb6 ? 1 : 2, rex, vaOf);
      return fin("movzx", [m.reg, m.rm], w, p - start + m.size);
    }
    if (op2 === 0xbe || op2 === 0xbf) {
      const m = decodeModrm(buf, p, end, op2 === 0xbe ? 1 : 2, rex, vaOf);
      return fin("movsx", [m.reg, m.rm], w, p - start + m.size);
    }
    if (op2 === 0xbc || op2 === 0xbd) {
      const m = decodeModrm(buf, p, end, w, rex, vaOf);
      return fin(op2 === 0xbc ? "bsf" : "bsr", [m.reg, m.rm], w, p - start + m.size);
    }
    if (op2 >= 0xc8 && op2 <= 0xcf) {
      return fin("bswap", [{ kind: "reg", reg: regName(op2 - 0xc8, w, rex), width: w }], w);
    }
    if (op2 === 0x10 || op2 === 0x11) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      const base = repPrefix === 1 ? "movsd" : repPrefix === 2 ? "movss" : op66 ? "movupd" : "movups";
      const mnem = op2 === 0x10 ? base : base + " (store)";
      return fin(mnem, op2 === 0x10 ? [m.reg, m.rm] : [m.rm, m.reg], 16, p - start + m.size);
    }
    if (op2 === 0x28 || op2 === 0x29) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      return fin(op66 ? (op2 === 0x28 ? "movapd" : "movapd(store)") : (op2 === 0x28 ? "movaps" : "movaps(store)"), [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x2a) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      return fin(repPrefix === 1 ? "cvtsi2sd" : "cvtsi2ss", [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x2c) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      return fin(repPrefix === 1 ? "cvttsd2si" : "cvttss2si", [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x57 || op2 === 0x58) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      const mn = repPrefix === 1 ? (op2 === 0x57 ? "xorpd" : "addsd") : repPrefix === 2 ? (op2 === 0x57 ? "xorps" : "addss") : (op2 === 0x57 ? "xorps" : "addps");
      return fin(mn, [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x2e || op2 === 0x2f) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      return fin(repPrefix === 1 ? "ucomisd" : "ucomiss", [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x12 || op2 === 0x13) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      return fin(op2 === 0x12 ? "movlpd" : "movlpd(store)", [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x14 || op2 === 0x15) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      return fin(op2 === 0x14 ? "unpcklpd" : "unpckhpd", [m.reg, m.rm], 16, p - start + m.size);
    }
    if (op2 === 0x6e || op2 === 0x6f || op2 === 0x7e || op2 === 0x7f || op2 === 0xd6) {
      const m = decodeModrm(buf, p, end, 16, rex, vaOf);
      const mn = op66 ? (op2 === 0x6e ? "movq" : op2 === 0x6f ? "movdqa" : op2 === 0x7e ? "movq(store)" : op2 === 0x7f ? "movdqa(store)" : "movq(store)") : (op2 === 0x6e ? "movd" : "movq");
      return fin(mn, [m.reg, m.rm], 16, p - start + m.size);
    }
    return bad(2);

    function fin(mnem: string, ops: Operand[], width: number, sizeOverride?: number, _o?: Operand[]): Decoded {
      return { va, size: sizeOverride ?? p - start, mnem, ops, width, ok: true };
    }
  }

  const w = rex.w ? 8 : op66 ? 2 : 4;

  // --- ALU blogu (add/or/adc/sbb/and/sub/xor/cmp) ---
  if (main <= 0x3d) {
    const group = main >> 3;
    const form = main & 7;
    const mnem = GRP1[group];
    if (form === 0 || form === 1) {
      // op r/m, r
      const width2 = form === 0 ? 1 : w;
      const m = decodeModrm(buf, p, end, width2, rex, vaOf);
      return fin(mnem, [m.rm, m.reg], width2, p - start + m.size);
    }
    if (form === 2 || form === 3) {
      // op r, r/m
      const width2 = form === 2 ? 1 : w;
      const m = decodeModrm(buf, p, end, width2, rex, vaOf);
      return fin(mnem, [m.reg, m.rm], width2, p - start + m.size);
    }
    if (form === 4) {
      // AL e, imm8
      if (p >= end) return bad(1);
      const imm = buf.readInt8(p);
      p += 1;
      return fin(mnem, [{ kind: "reg", reg: rex.present && rex.b ? "dil" : "al", width: 1 }, { kind: "imm", value: immSigned(imm), size: 1 }], 1);
    }
    if (form === 5) {
      const width2 = op66 ? 2 : 4;
      if (p + width2 > end) return bad(1);
      const imm = op66 ? buf.readInt16LE(p) : buf.readInt32LE(p);
      p += width2;
      return fin(mnem, [{ kind: "reg", reg: op66 ? "ax" : "eax", width: width2 }, { kind: "imm", value: immSigned(imm), size: width2 }], width2);
    }
    return bad(1); // form 6/7: 64-bit modunda gecersiz
  }

  // --- push/pop reg ---
  if (main >= 0x50 && main <= 0x57) return fin("push", [{ kind: "reg", reg: regName(main - 0x50, 8, rex), width: 8 }], 8);
  if (main >= 0x58 && main <= 0x5f) return fin("pop", [{ kind: "reg", reg: regName(main - 0x58, 8, rex), width: 8 }], 8);

  if (main === 0x68) {
    if (p + 4 > end) return bad(1);
    const imm = buf.readInt32LE(p);
    p += 4;
    return fin("push", [{ kind: "imm", value: immSigned(imm), size: 4 }], 8);
  }
  if (main === 0x6a) {
    if (p >= end) return bad(1);
    const imm = buf.readInt8(p);
    p += 1;
    return fin("push", [{ kind: "imm", value: immSigned(imm), size: 1 }], 8);
  }
  if (main === 0x69 || main === 0x6b) {
    const m = decodeModrm(buf, p, end, w, rex, vaOf);
    p += m.size;
    if (main === 0x69) {
      if (p + 4 > end) return bad(1);
      const imm = buf.readInt32LE(p);
      p += 4;
      return fin("imul", [m.reg, m.rm, { kind: "imm", value: immSigned(imm), size: 4 }], w);
    }
    if (p >= end) return bad(1);
    const imm = buf.readInt8(p);
    p += 1;
    return fin("imul", [m.reg, m.rm, { kind: "imm", value: immSigned(imm), size: 1 }], w);
  }

  if (main >= 0x70 && main <= 0x7f) {
    if (p >= end) return bad(1);
    const rel = buf.readInt8(p);
    p += 1;
    return fin(JCC8[main - 0x70], [{ kind: "imm", value: vaOf(p) + rel, size: 1 }], w);
  }

  if (main === 0x80 || main === 0x81 || main === 0x83) {
    const width2 = main === 0x80 ? 1 : w;
    const modrmByte = buf[p];
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    p += m.size;
    const opName = GRP1[(modrmByte >> 3) & 7];
    if (main === 0x81) {
      const immSize = op66 ? 2 : 4;
      if (p + immSize > end) return bad(1);
      const imm = op66 ? buf.readInt16LE(p) : buf.readInt32LE(p);
      p += immSize;
      return fin(opName, [m.rm, { kind: "imm", value: immSigned(imm), size: immSize }], width2);
    }
    if (p >= end) return bad(1);
    const imm = buf.readInt8(p);
    p += 1;
    return fin(opName, [m.rm, { kind: "imm", value: immSigned(imm), size: 1 }], width2);
  }

  if (main === 0x84 || main === 0x85) {
    const width2 = main === 0x84 ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    return fin("test", [m.rm, m.reg], width2, p - start + m.size);
  }
  if (main === 0x86 || main === 0x87) {
    const width2 = main === 0x86 ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    return fin("xchg", [m.rm, m.reg], width2, p - start + m.size);
  }
  if (main === 0x88 || main === 0x89 || main === 0x8a || main === 0x8b) {
    const width2 = main === 0x88 || main === 0x8a ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    if (main === 0x88 || main === 0x89) return fin("mov", [m.rm, m.reg], width2, p - start + m.size);
    return fin("mov", [m.reg, m.rm], width2, p - start + m.size);
  }
  if (main === 0x8d) {
    const m = decodeModrm(buf, p, end, w, rex, vaOf);
    return fin("lea", [m.reg, m.rm], w, p - start + m.size);
  }
  if (main === 0x8f) {
    const m = decodeModrm(buf, p, end, w, rex, vaOf);
    return fin("pop", [m.rm], w, p - start + m.size);
  }
  if (main === 0x90) return fin(rex.present ? "xchg rax,rax (nop)" : "nop", [], w);
  if (main === 0x98) return fin(rex.w ? "cdqe" : "cwde", [], w);
  if (main === 0x99) return fin(rex.w ? "cqo" : "cdq", [], w);
  if (main === 0x9c) return fin("pushfq", [], 8);
  if (main === 0x9d) return fin("popfq", [], 8);

  if (main >= 0xb0 && main <= 0xb7) {
    if (p >= end) return bad(1);
    const imm = buf[p];
    p += 1;
    return fin("mov", [{ kind: "reg", reg: regName(main - 0xb0, 1, rex), width: 1 }, { kind: "imm", value: imm, size: 1 }], 1);
  }
  if (main >= 0xb8 && main <= 0xbf) {
    const reg = regName(main - 0xb8, rex.w ? 8 : w, rex);
    if (rex.w) {
      if (p + 8 > end) return bad(1);
      const imm = buf.readBigInt64LE(p);
      p += 8;
      return fin("movabs", [{ kind: "reg", reg, width: 8 }, { kind: "imm", value: Number(imm), size: 8 }], 8);
    }
    const immSize = op66 ? 2 : 4;
    if (p + immSize > end) return bad(1);
    const imm = op66 ? buf.readInt16LE(p) : buf.readInt32LE(p);
    p += immSize;
    return fin("mov", [{ kind: "reg", reg, width: w }, { kind: "imm", value: immSigned(imm), size: immSize }], w);
  }

  if (main === 0xc0 || main === 0xc1) {
    const width2 = main === 0xc0 ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    p += m.size;
    const mrm = buf[p - m.size];
    const opName = GRP2[(mrm >> 3) & 7];
    if (p >= end) return bad(1);
    const imm = buf[p];
    p += 1;
    return fin(opName, [m.rm, { kind: "imm", value: imm, size: 1 }], width2);
  }
  if (main === 0xc2) {
    if (p + 2 > end) return bad(1);
    const imm = buf.readUInt16LE(p);
    p += 2;
    return fin("ret", [{ kind: "imm", value: imm, size: 2 }], w);
  }
  if (main === 0xc3) return fin("ret", [], w);
  if (main === 0xc6 || main === 0xc7) {
    const width2 = main === 0xc6 ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    p += m.size;
    const mrm = buf[p - m.size];
    if (((mrm >> 3) & 7) !== 0) return bad(p - start);
    if (main === 0xc6) {
      if (p >= end) return bad(1);
      const imm = buf[p];
      p += 1;
      return fin("mov", [m.rm, { kind: "imm", value: imm, size: 1 }], 1);
    }
    const immSize = op66 ? 2 : 4;
    if (p + immSize > end) return bad(1);
    const imm = op66 ? buf.readInt16LE(p) : buf.readInt32LE(p);
    p += immSize;
    return fin("mov", [m.rm, { kind: "imm", value: immSigned(imm), size: immSize }], width2);
  }
  if (main === 0xc9) return fin("leave", [], w);

  if (main === 0xd0 || main === 0xd1 || main === 0xd2 || main === 0xd3) {
    const width2 = main <= 0xd1 ? (main === 0xd0 ? 1 : w) : main === 0xd2 ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    const mrm = buf[p];
    const opName = GRP2[(mrm >> 3) & 7];
    return fin(opName, [m.rm, { kind: "reg", reg: main >= 0xd2 ? "cl" : "1", width: 1 }], width2, p - start + m.size);
  }

  if (main === 0xe8) {
    if (p + 4 > end) return bad(1);
    const rel = buf.readInt32LE(p);
    p += 4;
    return fin("call", [{ kind: "imm", value: vaOf(p) + rel, size: 4 }], w);
  }
  if (main === 0xe9) {
    if (p + 4 > end) return bad(1);
    const rel = buf.readInt32LE(p);
    p += 4;
    return fin("jmp", [{ kind: "imm", value: vaOf(p) + rel, size: 4 }], w);
  }
  if (main === 0xeb) {
    if (p >= end) return bad(1);
    const rel = buf.readInt8(p);
    p += 1;
    return fin("jmp", [{ kind: "imm", value: vaOf(p) + rel, size: 1 }], w);
  }

  if (main === 0xf6 || main === 0xf7) {
    const width2 = main === 0xf6 ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    const mrm = buf[p];
    const opName = GRP3[(mrm >> 3) & 7];
    const sub = (mrm >> 3) & 7;
    if (sub <= 1) {
      // test r/m, imm
      p += m.size;
      if (width2 === 1) { if (p >= end) return bad(1); const imm = buf[p]; p += 1; return fin("test", [m.rm, { kind: "imm", value: imm, size: 1 }], 1); }
      const immSize = op66 ? 2 : 4;
      if (p + immSize > end) return bad(1);
      const imm = op66 ? buf.readInt16LE(p) : buf.readInt32LE(p);
      p += immSize;
      return fin("test", [m.rm, { kind: "imm", value: immSigned(imm), size: immSize }], width2);
    }
    return fin(opName, [m.rm], width2, p - start + m.size);
  }

  if (main === 0xfe || main === 0xff) {
    const width2 = main === 0xfe ? 1 : w;
    const m = decodeModrm(buf, p, end, width2, rex, vaOf);
    const sub = (buf[p] >> 3) & 7;
    const names = main === 0xfe ? ["inc", "dec"] : ["inc", "dec", "call", "call far", "jmp", "jmp far", "push"];
    if (main === 0xff && sub >= 6) return bad(p - start);
    return fin(names[sub] ?? "unk", [m.rm], width2, p - start + m.size);
  }

  return bad(1);

  function fin(mnem: string, ops: Operand[], width: number, sizeOverride?: number): Decoded {
    return { va, size: sizeOverride ?? p - start, mnem, ops, width, ok: true };
  }
}

function insnText(d: Decoded, iatMap: Map<number, string>, stringAt: (va: number) => string | null, rdataLabel: (va: number) => string | null): string {
  let text = d.mnem;
  if (d.ops.length > 0) {
    text += " " + d.ops.map((o) => opText(o)).join(", ");
  }
  const comments: string[] = [];
  // yazi referansi
  for (const o of d.ops) {
    if (o.kind === "mem" && o.ripRel && o.ripTarget !== undefined) {
      const s = stringAt(o.ripTarget);
      if (s) comments.push(`"${s.slice(0, 60)}"`);
      const lbl = rdataLabel(o.ripTarget);
      if (lbl) comments.push(lbl);
    }
    if (o.kind === "imm") {
      const lbl = rdataLabel(o.value);
      if (lbl && d.mnem === "call") comments.push(lbl);
    }
  }
  // IAT cagrisi: call [rip->VA]
  if ((d.mnem === "call" || d.mnem === "jmp") && d.ops.length === 1 && d.ops[0].kind === "mem" && d.ops[0].ripRel && d.ops[0].ripTarget !== undefined) {
    const api = iatMap.get(d.ops[0].ripTarget);
    if (api) {
      text = text.replace(/\[.*\]/, api);
      comments.push(`IAT -> ${api}`);
    }
  }
  if (comments.length) text += `  ; ${comments.join(" ")}`;
  return text;
}

export interface DisasmResult {
  insns: AsmInsn[];
  unknownBytes: number;
}

/** [fileOff, fileOff+len) araligini cozer. */
export function disassemble(
  buf: Buffer,
  fileOff: number,
  len: number,
  vaStart: number,
  maxInsns = 4000,
  iatMap: Map<number, string> = new Map(),
  stringAt: (va: number) => string | null = () => null,
  rdataLabel: (va: number) => string | null = () => null,
): DisasmResult {
  const insns: AsmInsn[] = [];
  let unknown = 0;
  let p = fileOff;
  const end = Math.min(fileOff + len, buf.length);
  const vaOf = (off: number) => vaStart + (off - fileOff);

  while (p < end && insns.length < maxInsns) {
    const d = decodeAt(buf, p, end, vaOf);
    insns.push({
      va: vaOf(p),
      size: d.size,
      text: d.ok ? insnText(d, iatMap, stringAt, rdataLabel) : `db 0x${buf[p].toString(16).padStart(2, "0").toUpperCase()}`,
    });
    if (!d.ok) unknown++;
    p += Math.max(1, d.size);
  }
  return { insns, unknownBytes: unknown };
}

// ---------------------------------------------------------------------------
// Tahmini pseudo-C uretici
// ---------------------------------------------------------------------------

export interface PseudoContext {
  strings: Map<number, string>; // VA -> string
  iatMap: Map<number, string>; // IAT slot RVA -> "dll!fn"
  fnLabels: Map<number, string>; // RVA -> sub_XXX / export adi
  rdataLabels: Map<number, string>; // VA -> vftable / veri etiketi
}

export function buildPseudo(
  insns: AsmInsn[],
  fnVa: number,
  ctx: PseudoContext,
  maxLines = 200,
): string {
  const L: string[] = [];
  const argRegs = ["rcx", "rdx", "r8", "r9"];
  const argState = new Map<string, string>(); // reg -> son bilinen kaynak
  let frameSize = 0;
  const saved: string[] = [];
  let returns = 0;
  let lineCount = 0;

  const srcOf = (va: number): string | null => {
    const s = ctx.strings.get(va);
    if (s) return `"${s.slice(0, 48)}"`;
    const rl = ctx.rdataLabels.get(va);
    if (rl) return rl;
    const fn = ctx.fnLabels.get(va);
    if (fn) return fn;
    return null;
  };

  L.push("void __fastcall sub_" + fnVa.toString(16).toUpperCase() + "(...)");
  L.push("{");
  lineCount += 2;

  for (const ins of insns) {
    if (lineCount >= maxLines) break;
    const t = ins.text;
    const m = t.match(/^(\S+)(?:\s+(.*))?/);
    if (!m) continue;
    const mnem = m[1];
    const rest = (m[2] ?? "").trim();
    const base = rest.split(";")[0].trim();

    if (mnem === "push" && /^r[a-z0-9]+$/.test(base)) saved.push(base);
    if (mnem === "sub" && base.startsWith("rsp,")) {
      const v = base.split(",")[1]?.trim();
      frameSize = v ? parseInt(v, 16) : 0;
    }
    if (mnem === "mov" || mnem === "movabs" || mnem === "lea") {
      const parts = base.split(",");
      if (parts.length === 2) {
        const dst = parts[0].trim();
        const srct = parts[1].trim();
        if (argRegs.includes(dst)) {
          let v = srct;
          const immMatch = srct.match(/^0x[0-9A-F]+$/);
          if (immMatch) v = srct;
          const memMatch = srct.match(/^\[(0x[0-9A-F]+)\]$/);
          if (memMatch) {
            const va = parseInt(memMatch[1], 16);
            const known = srcOf(va);
            if (known) v = known;
          }
          argState.set(dst, v);
        }
      }
    }

    if (mnem === "call") {
      const target = base.trim();
      let name = target;
      if (/^0x/.test(target)) {
        const va = parseInt(target, 16);
        name = ctx.fnLabels.get(va) ?? `sub_${va.toString(16).toUpperCase()}`;
      } else if (/\[/.test(target)) {
        name = target.replace(/[[\]]/g, "");
      }
      const args = argRegs
        .map((r) => argState.get(r))
        .filter((v): v is string => v !== undefined)
        .slice(0, 4);
      L.push(`  ${name}(${args.join(", ")});`);
      lineCount++;
      argState.clear();
      continue;
    }
    if (mnem === "ret") {
      returns++;
      L.push(`  return;`);
      lineCount++;
      continue;
    }
    if (mnem.startsWith("j")) {
      // kocursuz kosullar icin tek satir yorum
      L.push(`  if (...) goto ${base};   // ${t}`);
      lineCount++;
      continue;
    }
    // deger donderen son komutlar: mov eax/eax, X; ret
    if (mnem === "test" || mnem === "cmp") {
      L.push(`  // ${t}`);
      lineCount++;
      continue;
    }
  }

  L.push("}");
  // baslik bilgisi
  const header: string[] = [];
  if (frameSize > 0) header.push(`stack frame 0x${frameSize.toString(16)}`);
  if (saved.length) header.push(`kaydedilen: ${saved.join(", ")}`);
  if (returns > 1) header.push(`${returns} donus noktasi`);
  if (header.length) L.unshift(`// tahmini - ${header.join(", ")}`);
  return L.join("\n");
}
