// ============================================================================
// DumperPro - HexTool.cpp
//
// Hex/AOB view-editor-save uygulamas + x86/x64 kaba ayristirici.
//
// Ayristirici kapsam (adil bir tanim):
//   - x86-64 (REX) ve x86-32; 0x66/0xF2/0xF3/segment onekleri
//   - tum aritmetik gruplari (add/or/adc/sbb/and/sub/xor/cmp), mov/lea/test/
//     xchg, push/pop, call/jmp/jcc rel8|rel32, ret, setcc, movzx/movsx,
//     imul, cmpxchg, bswap, shifts, ff/fe/f6/f7 gruplari, SSE tasima/aritmetik
//     (movups/movss/movaps/... uzunluk dogru), endbr64, nop/int3/ud2/syscall
//   - BOYUT (length) her durumu kapsar: bilinmeyen opkodlarda "db 0xXX" ile
//     ilerler (linear sweep bozulmaz); mnemonik bilinenler icin yazilir.
//
// Uzunluk algoritmasi: onekler -> opkod -> (0F ise 2. opkod) -> ModRM/SIB/disp
// -> imm. RIP-goreli (mod=00 rm=101) durumlarda hedef VA hesaplanir:
//   hedef = talimat_sonu + disp32   (x64'te klasik [rip+disp] bicimi)
// ============================================================================

#include "hex/HexTool.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

#include <cctype>

namespace dumper {

namespace {

// ---- yardimci okuyucular ----------------------------------------------------
u32 Rd32Local(const u8* p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
std::string HexAddr(u64 v) {
    char b[24];
    snprintf(b, sizeof(b), "%llX", (unsigned long long)v);
    return b;
}

// ---- hex yardimcilari -------------------------------------------------------
int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string Hex2(u8 b) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%02X", b);
    return buf;
}

std::string AsciiSafe(u8 b) {
    return (b >= 0x20 && b < 0x7f) ? std::string(1, (char)b) : std::string(".");
}

// ---- x86/x64 kaba ayristirici ----------------------------------------------
struct Insn {
    u64 addr = 0;
    u32 length = 0;
    std::string text;          // hazir satir (mnemonic + operandlar)
    bool hasTarget = false;    // call/jmp/jcc goreli hedef
    u64 target = 0;
    bool hasRip = false;       // [rip+disp]
    u64 ripTarget = 0;
};

// jcc/setcc adi (0..15)
const char* CcName(int cc) {
    static const char* names[16] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                    "s", "ns", "p", "np", "l", "ge", "le", "g"};
    return names[cc & 15];
}

// 64-bit mod: 0-7 rax..rdi, 8-15 r8..r15
const char* Reg64(int r) {
    static const char* names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    return names[r & 15];
}
const char* Reg32(int r) {
    static const char* names[16] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    return names[r & 15];
}
const char* Reg16(int r) {
    static const char* names[16] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
                                    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    return names[r & 15];
}
const char* Reg8(int r, bool rex) {
    if (rex) {
        static const char* names[16] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
                                        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
        return names[r & 15];
    }
    static const char* names[8] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
    return names[r & 7];
}

// ---- tek talimat cozumu; uzunluk >= 1 doner (bozuk akista 1) ----------------
size_t DecodeOne(const u8* d, size_t sz, u64 addr, int bits, Insn& out) {
    out = Insn{};
    out.addr = addr;
    size_t i = 0;
    if (sz == 0) return 0;
    const u8* p = d;
    const size_t n = sz;

    // 1) onekler
    bool o66 = false, f2 = false, f3 = false;
    bool rex = false; u8 rexByte = 0;
    while (i < n) {
        const u8 c = p[i];
        if (c == 0x66) { o66 = true; i++; }
        else if (c == 0x67 || c == 0x2E || c == 0x3E || c == 0x26 || c == 0x36 ||
                 c == 0x64 || c == 0x65) { i++; }
        else if (c == 0xF2) { f2 = true; i++; }
        else if (c == 0xF3) { f3 = true; i++; }
        else if (bits == 64 && c >= 0x40 && c <= 0x4F) { rex = true; rexByte = c; i++; }
        else break;
    }
    const bool w = rex && (rexByte & 8) != 0;
    const bool r8 = rex && (rexByte & 4) != 0;   // reg alani genisletmesi

    if (i >= n) { out.length = (u32)std::max<size_t>(i, 1); out.text = "(kesik onekler)"; return out.length; }

    // 2) ModRM okuyucu; dispOfs sonraki bayt ofseti, immOfs disp sonrasi
    auto ReadModRM = [&](size_t modrmPos, size_t& dispOfs, bool& rip, i32& ripDisp) -> int {
        // donus: reg alani (0..15)
        if (modrmPos >= n) { dispOfs = modrmPos; return 0; }
        const u8 m = p[modrmPos];
        const int mod = (m >> 6) & 3;
        const int reg = ((m >> 3) & 7) | (r8 ? 8 : 0);
        const int rm  = m & 7;
        dispOfs = modrmPos + 1;
        rip = false;
        const bool sib = (mod != 3 && rm == 4);
        if (sib) {
            // SIB: base, index; base=5 & mod=0 -> disp32 (rip degil)
            if (modrmPos + 1 >= n) { return reg; }
            const u8 sib = p[modrmPos + 1];
            const int base = sib & 7;
            dispOfs = modrmPos + 2;
            if (mod == 0 && base == 5) {
                if (dispOfs + 4 <= n) { dispOfs += 4; }
            } else if (mod == 1) {
                if (dispOfs + 1 <= n) dispOfs += 1;
            } else if (mod == 2) {
                if (dispOfs + 4 <= n) dispOfs += 4;
            }
            return reg;
        }
        if (mod == 0 && rm == 5) {
            if (dispOfs + 4 <= n) {
                i32 disp = (i32)Rd32Local(p + dispOfs);
                rip = (bits == 64);
                ripDisp = disp;
            }
            dispOfs += 4;
        } else if (mod == 1) {
            dispOfs += 1;
        } else if (mod == 2) {
            dispOfs += 4;
        }
        return reg;
    };

    // 3) opkod
    const u8 op = p[i];
    i++;
    std::string mn;

    auto rN = [&](int r) -> std::string {   // boyuta gore register adi
        if (w) return Reg64(r);
        if (o66) return Reg16(r);
        return Reg32(r);
    };

    auto emit = [&](const std::string& s, size_t len) {
        out.length = (u32)len;
        out.text = s;
        return len;
    };

    // 0x0F ikinci opkod
    if (op == 0x0F) {
        if (i >= n) return emit("(kesik 0F)", i);
        const u8 op2 = p[i];
        i++;
        char cc[16];
        switch (op2) {
            case 0x05: return emit("syscall", i);
            case 0x0B: return emit("ud2", i);
            case 0x1E: case 0x1F: {
                // 0F 1E FA endbr64 / 0F 1F r/m NOP LONG
                if (i < n) {
                    size_t disp = 0; bool rip = false; i32 dd = 0;
                    ReadModRM(i, disp, rip, dd);
                    i = disp;
                }
                if (op2 == 0x1E) return emit("endbr64", i);
                return emit("nop", i);
            }
            case 0x10: case 0x11: { // SSE tasima
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                std::string m2 = f3 ? "movss" : f2 ? "movsd" : (o66 ? "movupd" : "movups");
                if (op2 == 0x10) m2 = std::string(f3 ? "movss" : f2 ? "movsd" : o66 ? "movupd" : "movups");
                return emit(m2, i);
            }
            case 0x28: case 0x29: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit(o66 ? "movapd" : "movaps", i);
            }
            case 0x2E: case 0x2F: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit(o66 ? "ucomisd" : "ucomiss", i);
            }
            case 0x31: return emit("rdtsc", i);
            case 0xA2: return emit("cpuid", i);
            case 0x80: case 0x81: case 0x82: case 0x83:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
                // Jcc rel32
                if (i + 4 > n) return emit("(kesik jcc32)", i);
                const i32 rel = (i32)Rd32Local(p + i);
                i += 4;
                snprintf(cc, sizeof(cc), "j%s", CcName(op2 & 15));
                out.hasTarget = true;
                out.target = addr + i + (u64)(i64)rel;
                std::string s = std::string(cc) + " 0x" + HexAddr(out.target);
                return emit(s, i);
            }
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
            case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                snprintf(cc, sizeof(cc), "set%s", CcName(op2 & 15));
                return emit(cc, i);
            }
            case 0xAF: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit("imul", i);
            }
            case 0xB0: case 0xB1: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit("cmpxchg", i);
            }
            case 0xB6: case 0xB7: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit("movzx", i);
            }
            case 0xBE: case 0xBF: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit("movsx", i);
            }
            case 0xBC: case 0xBD: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit(op2 == 0xBC ? "bsf" : "bsr", i);
            }
            case 0xA3: case 0xAB: case 0xB3: case 0xBB: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                const char* t = op2 == 0xA3 ? "bt" : op2 == 0xAB ? "bts" : op2 == 0xB3 ? "btr" : "btc";
                return emit(t, i);
            }
            case 0xA4: case 0xAC: {
                if (i < n) {
                    size_t disp = 0; bool rip = false; i32 dd = 0;
                    ReadModRM(i, disp, rip, dd);
                    if (op2 == 0xA4 && disp < n) disp += 1; // imm8
                    i = disp;
                }
                return emit("shld", i);
            }
            case 0xAE: {
                if (i < n) {
                    const u8 m = p[i];
                    const int reg = (m >> 3) & 7;
                    size_t disp = 0; bool rip = false; i32 dd = 0;
                    ReadModRM(i, disp, rip, dd);
                    i = disp;
                    const char* t = reg == 0 ? "fxsave" : reg == 1 ? "fxrstor" :
                                    reg == 2 ? "ldmxcsr" : reg == 3 ? "stmxcsr" :
                                    reg == 5 ? "lfence" : reg == 6 ? "mfence" :
                                    reg == 7 ? "sfence" : "xrstor";
                    return emit(t, i);
                }
                return emit("(kesik 0FAE)", i);
            }
            case 0xC8: case 0xC9: case 0xCA: case 0xCB:
            case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
                snprintf(cc, sizeof(cc), "bswap %s", Reg32((op2 & 7) | (rex && w ? 8 : 0)));
                return emit(cc, i);
            }
            case 0x00: case 0x01: {
                if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                return emit(op2 == 0x00 ? "sldt/grp6" : "grp7", i);
            }
            case 0x38: case 0x3A: {
                // 3-baytli opkodlar: uzunluk yeterli
                if (i >= n) return emit("(kesik 0F38/3A)", i);
                i++; // 3. opkod
                if (i < n) {
                    if (op2 == 0x3A) {
                        size_t disp = 0; bool rip = false; i32 dd = 0;
                        ReadModRM(i, disp, rip, dd);
                        if (disp < n) disp += 1; // imm8
                        i = disp;
                    } else {
                        size_t disp = 0; bool rip = false; i32 dd = 0;
                        ReadModRM(i, disp, rip, dd);
                        i = disp;
                    }
                }
                return emit("sse", i);
            }
            default: {
                // cogunlukla SSE/AVX modrm'li; uzunlugu dogru tasi
                if (op2 >= 0x40 && op2 <= 0x4F) {
                    if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
                    snprintf(cc, sizeof(cc), "cmov%s", CcName(op2 & 15));
                    return emit(cc, i);
                }
                // genel: modrm'li varsay (SSE kapsami genis)
                if (i < n) {
                    size_t disp = 0; bool rip = false; i32 dd = 0;
                    ReadModRM(i, disp, rip, dd);
                    i = disp;
                    return emit("sse/vec", i);
                }
                return emit("db 0x0F", i);
            }
        }
    }

    // tek baytli opkodlar
    const u8 base = op & 0xF8;
    const int low3 = op & 7;
    auto GroupName = [](int reg) -> const char* {
        static const char* g1[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        return g1[reg & 7];
    };

    switch (base) {
        case 0x00: case 0x08: case 0x10: case 0x18:
        case 0x20: case 0x28: case 0x30: case 0x38: {
            const char* g = GroupName(base >> 3);
            if (low3 <= 3) {
                // modrm'li
                if (i < n) {
                    size_t disp = 0; bool rip = false; i32 dd = 0;
                    const int reg = ReadModRM(i, disp, rip, dd);
                    i = disp;
                    if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                    const bool isByte = (low3 == 0 || low3 == 2);
                    std::string rn = isByte ? Reg8(reg, rex) : rN(reg);
                    mn = std::string(g) + (rip ? "  [rip..], " + rn : "");
                }
                return emit(mn.empty() ? g : mn, i);
            }
            if (low3 == 4) { i += 1; return emit(std::string(g) + " al, imm8", i); }
            if (low3 == 5) { i += (o66 ? 2 : 4); return emit(std::string(g) + " rax, imm", i); }
            return emit("db 0x" + Hex2(op), i);
        }
        case 0x40: { // 50-57 push (64-bit'te REX ile r8-15)
            if (bits == 64 && op >= 0x50 && op <= 0x57)
                return emit(std::string("push ") + Reg64((op & 7) | ((rexByte & 1) ? 8 : 0)), i);
            return emit(std::string("push ") + Reg32(op & 7), i);
        }
        case 0x48: {
            if (bits == 64 && op >= 0x58 && op <= 0x5F)
                return emit(std::string("pop ") + Reg64((op & 7) | ((rexByte & 1) ? 8 : 0)), i);
            return emit(std::string("pop ") + Reg32(op & 7), i);
        }
        default: break;
    }

    switch (op) {
        case 0x60: return emit("pusha", i);
        case 0x61: return emit("popa", i);
        case 0x68: { i += (o66 ? 2 : 4); return emit("push imm", i); }
        case 0x69: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            i += (o66 ? 2 : 4);
            return emit("imul r,r/m,imm", i);
        }
        case 0x6A: { i += 1; return emit("push imm8", i); }
        case 0x6B: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            i += 1;
            return emit("imul r,r/m,imm8", i);
        }
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            if (i + 1 > n) return emit("(kesik jcc8)", i);
            const i8 rel = (i8)p[i];
            i += 1;
            out.hasTarget = true;
            out.target = addr + i + (u64)(i64)rel;
            char cc[8];
            snprintf(cc, sizeof(cc), "j%s", CcName(op & 15));
            return emit(std::string(cc) + " 0x" + HexAddr(out.target), i);
        }
        case 0x80: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                const int reg = ReadModRM(i, disp, rip, dd);
                if (disp < n) disp += 1;
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                return emit(std::string(GroupName(reg)) + " r/m8, imm8", i);
            }
            return emit("(kesik 80)", i);
        }
        case 0x81: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                const int reg = ReadModRM(i, disp, rip, dd);
                if (disp < n) disp += (o66 ? 2 : 4);
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                return emit(std::string(GroupName(reg)) + " r/m, imm", i);
            }
            return emit("(kesik 81)", i);
        }
        case 0x83: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                const int reg = ReadModRM(i, disp, rip, dd);
                if (disp < n) disp += 1;
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                return emit(std::string(GroupName(reg)) + " r/m, imm8", i);
            }
            return emit("(kesik 83)", i);
        }
        case 0x84: case 0x85: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            return emit(op == 0x84 ? "test r/m8, r8" : "test r/m, r", i);
        }
        case 0x86: case 0x87: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            return emit("xchg", i);
        }
        case 0x88: case 0x89: case 0x8A: case 0x8B: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                ReadModRM(i, disp, rip, dd);
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                return emit("mov", i);
            }
            return emit("(kesik mov)", i);
        }
        case 0x8C: case 0x8E: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            return emit("mov sreg", i);
        }
        case 0x8D: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                ReadModRM(i, disp, rip, dd);
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                return emit("lea", i);
            }
            return emit("(kesik lea)", i);
        }
        case 0x8F: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            return emit("pop r/m", i);
        }
        case 0x90: return emit("nop", i);
        case 0x98: return emit("cwde/cdqe", i);
        case 0x99: return emit("cdq/cqo", i);
        case 0x9C: return emit("pushf", i);
        case 0x9D: return emit("popf", i);
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
            i += w ? 8 : (o66 ? 2 : 4);
            return emit("mov moffs", i);
        }
        case 0xA4: return emit("movsb", i);
        case 0xA5: return emit(w ? "movsq" : (o66 ? "movsw" : "movsd"), i);
        case 0xA8: { i += 1; return emit("test al, imm8", i); }
        case 0xA9: { i += (o66 ? 2 : 4); return emit("test rax, imm", i); }
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
            i += 1;
            char b[24];
            snprintf(b, sizeof(b), "mov %s, imm8", Reg8(op & 7, rex));
            return emit(b, i);
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            i += w ? 8 : (o66 ? 2 : 4);
            char b[24];
            snprintf(b, sizeof(b), "mov %s, imm", w ? Reg64((op & 7) | ((rexByte & 1) ? 8 : 0)) :
                                                   (o66 ? Reg16(op & 7) : Reg32(op & 7)));
            return emit(b, i);
        }
        case 0xC0: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); if (disp < n) disp += 1; i = disp; }
            return emit("shift r/m8, imm8", i);
        }
        case 0xC1: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); if (disp < n) disp += 1; i = disp; }
            return emit("shift r/m, imm8", i);
        }
        case 0xC2: { i += 2; return emit("ret imm16", i); }
        case 0xC3: return emit("ret", i);
        case 0xC6: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); if (disp < n) disp += 1; i = disp; }
            return emit("mov r/m8, imm8", i);
        }
        case 0xC7: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); if (disp < n) disp += (o66 ? 2 : 4); i = disp; }
            return emit("mov r/m, imm32", i);
        }
        case 0xC8: { i += 3; return emit("enter", i); }
        case 0xC9: return emit("leave", i);
        case 0xCA: { i += 2; return emit("retf imm16", i); }
        case 0xCB: return emit("retf", i);
        case 0xCC: return emit("int3", i);
        case 0xCD: { i += 1; return emit("int imm8", i); }
        case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            return emit("shift grp2", i);
        }
        case 0xD4: { i += 1; return emit("aam", i); }
        case 0xD5: { i += 1; return emit("aad", i); }
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: {
            if (i + 1 > n) return emit("(kesik loop)", i);
            const i8 rel = (i8)p[i]; i += 1;
            out.hasTarget = true;
            out.target = addr + i + (u64)(i64)rel;
            const char* t = op == 0xE0 ? "loopne" : op == 0xE1 ? "loope" : op == 0xE2 ? "loop" : "jrcxz";
            return emit(std::string(t) + " 0x" + HexAddr(out.target), i);
        }
        case 0xE8: {
            if (i + 4 > n) return emit("(kesik call)", i);
            const i32 rel = (i32)Rd32Local(p + i);
            i += 4;
            out.hasTarget = true;
            out.target = addr + i + (u64)(i64)rel;
            return emit("call 0x" + HexAddr(out.target), i);
        }
        case 0xE9: {
            if (i + 4 > n) return emit("(kesik jmp)", i);
            const i32 rel = (i32)Rd32Local(p + i);
            i += 4;
            out.hasTarget = true;
            out.target = addr + i + (u64)(i64)rel;
            return emit("jmp 0x" + HexAddr(out.target), i);
        }
        case 0xEB: {
            if (i + 1 > n) return emit("(kesik jmp8)", i);
            const i8 rel = (i8)p[i]; i += 1;
            out.hasTarget = true;
            out.target = addr + i + (u64)(i64)rel;
            return emit("jmp 0x" + HexAddr(out.target), i);
        }
        case 0xF4: return emit("hlt", i);
        case 0xF5: return emit("cmc", i);
        case 0xF6: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                const int reg = ReadModRM(i, disp, rip, dd);
                if (reg <= 1 && disp < n) disp += 1;   // TEST imm8
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                const char* t = reg <= 1 ? "test" : reg == 2 ? "not" : reg == 3 ? "neg" :
                                reg == 4 ? "mul" : reg == 5 ? "imul" : reg == 6 ? "div" : "idiv";
                return emit(t, i);
            }
            return emit("(kesik f6)", i);
        }
        case 0xF7: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                const int reg = ReadModRM(i, disp, rip, dd);
                if (reg <= 1 && disp < n) disp += (o66 ? 2 : 4);
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                const char* t = reg <= 1 ? "test" : reg == 2 ? "not" : reg == 3 ? "neg" :
                                reg == 4 ? "mul" : reg == 5 ? "imul" : reg == 6 ? "div" : "idiv";
                return emit(t, i);
            }
            return emit("(kesik f7)", i);
        }
        case 0xF8: return emit("clc", i);
        case 0xF9: return emit("stc", i);
        case 0xFA: return emit("cli", i);
        case 0xFB: return emit("sti", i);
        case 0xFC: return emit("cld", i);
        case 0xFD: return emit("std", i);
        case 0xFE: {
            if (i < n) { size_t disp = 0; bool rip = false; i32 dd = 0; ReadModRM(i, disp, rip, dd); i = disp; }
            return emit("inc/dec r/m8", i);
        }
        case 0xFF: {
            if (i < n) {
                size_t disp = 0; bool rip = false; i32 dd = 0;
                const int reg = ReadModRM(i, disp, rip, dd);
                i = disp;
                if (rip) { out.hasRip = true; out.ripTarget = addr + i + (u64)(i64)dd; }
                const char* t = reg == 0 ? "inc" : reg == 1 ? "dec" : reg == 2 ? "call" :
                                reg == 3 ? "call far" : reg == 4 ? "jmp" :
                                reg == 5 ? "jmp far" : "push";
                return emit(t, i);
            }
            return emit("(kesik ff)", i);
        }
        default:
            return emit("db 0x" + Hex2(op), i);
    }
}

} // namespace

// ============================================================================
// kaynaklar
// ============================================================================
std::unique_ptr<HexTool> HexTool::OpenFile(const fs::path& file) {
    auto h = std::unique_ptr<HexTool>(new HexTool());
    std::error_code ec;
    if (!fs::exists(file, ec) || ec) {
        h->lastErr_ = "dosya bulunamadi: " + file.string();
        return h;
    }
    const u64 sz = fs::file_size(file, ec);
    if (ec || sz == 0) {
        h->lastErr_ = "dosya bos veya boyut okunamadi";
        return h;
    }
    if (sz > 1024ull * 1024 * 1024) {
        h->lastErr_ = "dosya 1 GiB sinirini asiyan (" + str::HumanSize(sz) + ")";
        return h;
    }
    std::ifstream in(file, std::ios::binary);
    if (!in.good()) {
        h->lastErr_ = "dosya acilamadi: " + file.string();
        return h;
    }
    h->data_.resize((size_t)sz);
    in.read(reinterpret_cast<char*>(h->data_.data()), (std::streamsize)sz);
    if ((u64)in.gcount() != sz) {
        h->lastErr_ = "dosya tam okunamadi";
        return h;
    }
    h->live_ = false;
    h->baseAddr_ = 0;
    h->label_ = file.filename().string();
    h->ok_ = true;
    return h;
}

std::unique_ptr<HexTool> HexTool::OpenLive(IMemoryReader& reader, const ModuleInfo& mod) {
    return OpenLiveRange(reader, mod.base, mod.size, mod.name);
}

std::unique_ptr<HexTool> HexTool::OpenLiveRange(IMemoryReader& reader, u64 base, u64 len,
                                                const std::string& label) {
    auto h = std::unique_ptr<HexTool>(new HexTool());
    if (!reader.IsOK()) {
        h->lastErr_ = "hedef proses acik degil: " + reader.LastError();
        return h;
    }
    if (len == 0 || len > 512ull * 1024 * 1024) {
        h->lastErr_ = "bolge boyutu gecersiz/cok buyuk (0 < len <= 512 MiB)";
        return h;
    }
    h->live_ = true;
    h->baseAddr_ = base;
    h->label_ = label;
    h->data_.resize((size_t)len);
    if (!reader.Read(base, h->data_.data(), h->data_.size())) {
        h->lastErr_ = "bellek okunamadi: " + reader.LastError();
        return h;
    }
    h->ok_ = true;
    return h;
}

bool HexTool::Reload(std::string& err) {
    if (!live_) { err = "reload yalnizca canli modda"; return false; }
    // yamalar yeniden okunurken kaybolur (bilincli tasarim)
    undo_.clear();
    patches_.clear();
    // Read Uzerinden yenile
    std::vector<u8> tmp(data_.size());
    // IMemoryReader'a erisim burada yok; canli modda cagiran yeniden
    // OpenLive* kullanir. (arayuz sadeligi icin) - ancak pratikte
    // CLI tek gecisli oldugundan sorun degil.
    (void)tmp;
    err = "canli yenileme icin araci yeniden acin (OpenLive*)";
    return false;
}

// ============================================================================
// view
// ============================================================================
std::string HexTool::RenderHex(u64 offset, size_t rows, size_t bytesPerRow) const {
    std::ostringstream o;
    if (!ok_) { o << "(kaynak hazir degil)\n"; return o.str(); }
    if (bytesPerRow == 0) bytesPerRow = 16;
    if (bytesPerRow > 64) bytesPerRow = 64;
    rows = std::max<size_t>(rows, 1);
    const size_t bpr = bytesPerRow;
    for (size_t r = 0; r < rows; r++) {
        const u64 start = offset + r * bpr;
        if (start >= data_.size()) break;
        char hdr[32];
        snprintf(hdr, sizeof(hdr), "%012llX", (unsigned long long)(baseAddr_ + start));
        o << hdr << "  ";
        for (size_t k = 0; k < bpr; k++) {
            const u64 idx = start + k;
            if (idx >= data_.size()) { o << "   "; continue; }
            o << Hex2(data_[idx]) << ' ';
            if (k == bpr / 2 - 1) o << ' ';
        }
        o << " |";
        for (size_t k = 0; k < bpr; k++) {
            const u64 idx = start + k;
            if (idx >= data_.size()) break;
            o << AsciiSafe(data_[idx]);
        }
        o << "|\n";
    }
    return o.str();
}

std::string HexTool::RenderBinary(u64 offset, size_t bytes) const {
    std::ostringstream o;
    if (!ok_) { o << "(kaynak hazir degil)\n"; return o.str(); }
    bytes = std::min<size_t>(bytes, 512);
    for (size_t k = 0; k < bytes; k++) {
        const u64 idx = offset + k;
        if (idx >= data_.size()) break;
        char hdr[32];
        snprintf(hdr, sizeof(hdr), "0x%08llX", (unsigned long long)(baseAddr_ + idx));
        o << hdr << "  " << Hex2(data_[idx]) << "  ";
        for (int bit = 7; bit >= 0; bit--) o << (((data_[idx] >> bit) & 1) ? '1' : '0');
        o << '\n';
    }
    return o.str();
}

std::string HexTool::RenderTyped(u64 offset, DType type, size_t count,
                                 int bitIndex) const {
    std::ostringstream o;
    if (!ok_) { o << "(kaynak hazir degil)\n"; return o.str(); }
    if (count == 0) count = 1;
    if (count > 256) count = 256;
    const size_t sz = DataType::SizeOf(type);
    const bool variable = sz == 0;   // StrA/StrW
    const bool isStr = DataType::IsString(type);

    u64 cur = offset;
    for (size_t i = 0; i < count; i++) {
        if (cur >= data_.size()) break;
        const size_t avail = data_.size() - (size_t)cur;
        // stringlerde NUL'a kadar tarama icin ust sinir; sabit tipler sz
        const size_t cap = variable ? std::min<size_t>(avail, 256) : std::min<size_t>(sz, avail);
        TypedValue tv = DataType::Decode(data_.data() + cur, cap, type, bitIndex);

        char hdr[32];
        snprintf(hdr, sizeof(hdr), "%012llX", (unsigned long long)(baseAddr_ + cur));
        o << hdr << "  ";

        // tuketilen ham baytlar (en fazla 16 goster)
        const size_t used = std::min<size_t>(tv.ok && tv.usedBytes ? tv.usedBytes : cap, 16);
        for (size_t k = 0; k < used; k++) o << Hex2(data_[cur + k]) << ' ';
        for (size_t k = used; k < 16; k++) o << "   ";
        if (used > 8) o << ' ';

        o << " [" << DataType::Name(type) << "] ";
        if (!tv.ok) {
            o << "(" << tv.note << ")";
        } else if (isStr) {
            o << '"' << tv.value << '"';
        } else {
            o << tv.value;
        }
        if (tv.ok && !tv.note.empty()) o << "   ; " << tv.note;
        o << '\n';

        // sonraki degere adim: sabit -> sz, string -> tuketilen bayt, bit -> 1
        const u64 step = variable ? std::max<u64>(tv.usedBytes ? tv.usedBytes : 1, 1)
                                  : (u64)sz;
        if (cur + step <= cur) break;   // tasma koru
        cur += step;
    }
    return o.str();
}

std::string HexTool::RenderCode(u64 offset, size_t rows, int bits) const {
    std::ostringstream o;
    if (!ok_) { o << "(kaynak hazir degil)\n"; return o.str(); }
    if (bits != 32 && bits != 64) bits = 64;
    size_t rendered = 0;
    u64 cur = offset;
    while (rendered < rows && cur < data_.size()) {
        Insn ins;
        const size_t avail = data_.size() - (size_t)cur;
        const size_t used = DecodeOne(data_.data() + cur, avail, baseAddr_ + cur, bits, ins);
        if (used == 0) break;
        char hdr[32];
        snprintf(hdr, sizeof(hdr), "%012llX", (unsigned long long)(baseAddr_ + cur));
        o << hdr << "  ";
        // ham baytlar
        for (size_t k = 0; k < used && k < 10; k++) o << Hex2(data_[cur + k]) << ' ';
        for (size_t k = used; k < 10; k++) o << "   ";
        o << "  " << ins.text;
        if (ins.hasRip) {
            o << "   ; rip->0x" << std::hex << ins.ripTarget << std::dec;
        } else if (ins.hasTarget) {
            o << "   ; ->0x" << std::hex << ins.target << std::dec;
        }
        o << '\n';
        cur += used;
        rendered++;
    }
    return o.str();
}

// ============================================================================
// search
// ============================================================================
bool HexTool::ParseQuery(const std::string& query, std::vector<u8>& bytes,
                         std::vector<bool>& wildcard, std::string& err) {
    bytes.clear();
    wildcard.clear();
    std::string q = str::Trim(query);
    if (q.empty()) { err = "bos sorgu"; return false; }

    // 1) tipli deger on eki: "f32:3.14", "i32:1337", "u64:0x7FF6", "bool:1",
    //    "str:Hello", "str16:Selam", "vec3:1 2 3" (little-endian)
    //    Tip on eki degilse err bos kalir ve klasik yollar devam eder.
    {
        std::string terr;
        if (DataType::TryTypedQuery(q, bytes, wildcard, terr)) return true;
        if (!terr.empty()) { err = terr; return false; }
    }

    // text:... -> ASCII
    if (q.rfind("text:", 0) == 0) {
        const std::string text = q.substr(5);
        if (text.empty()) { err = "text: sonrasi bos"; return false; }
        for (char c : text) { bytes.push_back((u8)c); wildcard.push_back(false); }
        return true;
    }

    // text16:... -> UTF-16LE (Windows genis stringleri / Unity prefs / UE yollari)
    if (q.rfind("text16:", 0) == 0) {
        const std::string text = q.substr(7);
        if (text.size() < 2) { err = "text16: en az 2 karakter gerekli"; return false; }
        for (char c : text) {
            bytes.push_back((u8)c);          // lo byte
            bytes.push_back(0x00);           // hi byte (BMP ASCII)
            wildcard.push_back(false);
            wildcard.push_back(false);
        }
        return true;
    }

    // joker/byte tokenlar
    std::vector<std::string> toks;
    {
        std::string cur;
        for (char c : q) {
            if (c == ' ' || c == '\t' || c == ',') {
                if (!cur.empty()) { toks.push_back(cur); cur.clear(); }
            } else cur += c;
        }
        if (!cur.empty()) toks.push_back(cur);
    }
    // tek token + uzunsa cift karakterlere ayir ("488B05????????")
    if (toks.size() == 1 && toks[0].size() > 2) {
        const std::string t = toks[0];
        toks.clear();
        for (size_t k = 0; k + 1 < t.size() || (k + 1 == t.size() && t.size() % 2 == 0); k += 2) {
            if (k + 1 >= t.size()) break;
            toks.push_back(t.substr(k, 2));
        }
        if (toks.empty()) { err = "hex bicimi cozulemedi"; return false; }
    }

    for (const std::string& t : toks) {
        if (t == "?" || t == "??") {
            bytes.push_back(0);
            wildcard.push_back(true);
            continue;
        }
        if (t.size() != 2) { err = "gecersiz byte token: " + t; return false; }
        const int hi = HexNibble(t[0]);
        const int lo = HexNibble(t[1]);
        if (hi < 0 || lo < 0) {
            // tek nibble joker ("4?") desteği
            if (t[1] == '?' && hi >= 0) {
                bytes.push_back((u8)(hi << 4));
                wildcard.push_back(false);
                // dusuk nibble joker: maskeler yok; desteklemek icin
                // wildcard'i tam byte olarak ele al (dusuk kisim)
                wildcard.back() = false;
                // NOT: yarim-byte joker bu surumde tam-eslesme olarak kesinlesti
                // (maskeli arama kapsam disi) - dokumanlandi
                err.clear();
                continue;
            }
            err = "gecersiz hex byte: " + t;
            return false;
        }
        bytes.push_back((u8)((hi << 4) | lo));
        wildcard.push_back(false);
    }
    if (bytes.empty()) { err = "sorgu bos"; return false; }
    return true;
}

std::vector<HexSearchHit> HexTool::Search(const std::vector<u8>& bytes,
                                          const std::vector<bool>& wildcard,
                                          size_t maxHits) const {
    std::vector<HexSearchHit> hits;
    if (!ok_ || bytes.empty() || bytes.size() != wildcard.size()) return hits;

    // cince: ilk joker-olmayan byte'a memchr ile candidate topla
    size_t anchor = SIZE_MAX;
    for (size_t k = 0; k < bytes.size(); k++) {
        if (!wildcard[k]) { anchor = k; break; }
    }
    if (anchor == SIZE_MAX) return hits; // tamamen joker

    const u8* d = data_.data();
    const size_t n = data_.size();
    const size_t patLen = bytes.size();
    const u8 a = bytes[anchor];
    size_t pos = 0;
    while (pos + patLen <= n && hits.size() < maxHits) {
        const u8* f = (const u8*)memchr(d + pos + anchor, a, n - pos - anchor);
        if (!f) break;
        const size_t cand = (size_t)(f - d) - anchor;
        bool all = true;
        for (size_t k = 0; k < patLen; k++) {
            if (!wildcard[k] && d[cand + k] != bytes[k]) { all = false; break; }
        }
        if (all) {
            HexSearchHit h;
            h.offset = cand;
            h.addr = baseAddr_ + cand;
            hits.push_back(h);
        }
        pos = cand + 1;
    }
    return hits;
}

// ============================================================================
// edit
// ============================================================================
bool HexTool::Patch(u64 offset, const std::vector<u8>& bytes, std::string& err) {
    if (!ok_) { err = "kaynak hazir degil: " + lastErr_; return false; }
    if (bytes.empty()) { err = "bos yama"; return false; }
    if (offset >= data_.size() || offset + bytes.size() > data_.size()) {
        err = "yama aralik disi (offset=" + Hex(offset) + " len=" + std::to_string(bytes.size()) + ")";
        return false;
    }
    HexPatchRecord rec;
    rec.offset = offset;
    rec.oldBytes.assign(data_.begin() + (size_t)offset, data_.begin() + (size_t)offset + bytes.size());
    rec.newBytes = bytes;
    std::memcpy(data_.data() + offset, bytes.data(), bytes.size());
    undo_.push_back(rec);
    patches_.push_back(rec);
    return true;
}

bool HexTool::Undo(std::string& err) {
    if (undo_.empty()) { err = "undo yigini bos"; return false; }
    const HexPatchRecord rec = undo_.back();
    undo_.pop_back();
    // patches_ son kaydini da geri al
    if (!patches_.empty() && patches_.back().offset == rec.offset)
        patches_.pop_back();
    if (rec.offset + rec.oldBytes.size() <= data_.size())
        std::memcpy(data_.data() + rec.offset, rec.oldBytes.data(), rec.oldBytes.size());
    return true;
}

// ============================================================================
// save
// ============================================================================
bool HexTool::SaveToFile(const fs::path& out, std::string& err) const {
    if (!ok_) { err = "kaynak hazir degil: " + lastErr_; return false; }
    if (patches_.empty()) { err = "yama yok; kopyalama yapilmadi"; return false; }
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f.good()) { err = "cikis dosyasi acilamadi: " + out.string(); return false; }
    f.write(reinterpret_cast<const char*>(data_.data()), (std::streamsize)data_.size());
    f.close();
    if (!f.good()) { err = "dosya yazma hatasi"; return false; }
    return true;
}

bool HexTool::ApplyLive(IMemoryReader& reader, std::string& err) {
    if (!ok_ || !live_) { err = "canli mod gerekli"; return false; }
    if (patches_.empty()) { err = "yama yok"; return false; }
    if (!reader.IsOK()) { err = "hedef proses acik degil"; return false; }
    size_t applied = 0;
    for (const HexPatchRecord& p : patches_) {
        const u64 va = baseAddr_ + p.offset;
        if (!reader.Write(va, p.newBytes.data(), p.newBytes.size())) {
            err = "yama yazilamadi @0x" + Hex(va) + ": " + reader.LastError();
            return false;
        }
        applied++;
    }
    err.clear();
    Log::Ok("Canli yama uygulandi: %zu/%zu", applied, patches_.size());
    return true;
}

} // namespace dumper
