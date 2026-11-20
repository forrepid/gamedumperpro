// ============================================================================
//  UnrealDumperX - pattern.h
//  Module 2 - Signature System.
//
//  IMPORTANT NOTE #12: every reusable signature is stored as a PAIR:
//      main signature   (IDA style: "48 8B 05 ?? ?? ?? ?? 48 85 C0")
//      extended sig     (16 bytes following the main hit, with relocation
//                        sensitive bytes wildcarded)
//  The pair is written into games.ini and re-resolved after game updates,
//  which is what keeps the dumper working without recompilation.
//
//  Also hosts small in-memory PE helpers (section map + import-name lookup)
//  used by the version scanner, anchor finder and thunk resolver.
// ============================================================================
#pragma once
#include "common.h"
#include "process.h"

namespace udx {

struct Pattern {
    std::vector<u8>  bytes;
    std::vector<bool> mask;   // true = must match, false = wildcard
    usize length() const { return bytes.size(); }
    bool empty() const { return bytes.empty(); }
};

Pattern parseIda(const std::string& sig);        // "48 8B 05 ?? ? ? 7? C3"
std::string patternToString(const Pattern& p);

// Scans one module's in-memory image. Returns 0 when not found.
uintptr_t scanModule(Process& proc, const ModuleInfo& mod, const Pattern& pat);
std::vector<uintptr_t> scanModuleAll(Process& proc, const ModuleInfo& mod,
                                     const Pattern& pat, usize maxHits = 256);
// Scans every committed executable range (for functions outside known modules).
std::vector<uintptr_t> scanCommitted(Process& proc, const Pattern& pat, usize maxHits = 256);

// Builds the 16-byte extended signature after a main hit. Wildcard rules:
//   * any 8-byte window whose u64 decodes inside the module range (RIP-rel
//     displacement into module data) -> wildcarded
//   * operand bytes right after rel32/rel8 control-flow opcodes
//     (E8/E9/74/75/EB/0F 8x) -> wildcarded
std::string buildExtendedSignature(Process& proc, const ModuleInfo& mod,
                                   uintptr_t hit, usize mainLength);

// Re-resolves a stored (main | extended) pair. Prefers the hit whose 16
// following bytes match the extended mask; falls back to the first main hit.
uintptr_t resolveSignaturePair(Process& proc, const ModuleInfo& mod,
                               const std::string& mainSig,
                               const std::string& extendedSig);

// ---- in-memory PE helpers --------------------------------------------------
struct PeSection { std::string name; uintptr_t start; size_t size; };
std::vector<PeSection> peSectionsOf(Process& proc, const ModuleInfo& mod);

// Resolves an IAT slot to "module!FunctionName" (used for import thunks).
std::string lookupImportName(Process& proc, const ModuleInfo& mod,
                             uintptr_t iatSlot);

// RVA helper.
inline u64 rva(const ModuleInfo& m, uintptr_t addr) { return addr - m.base; }

} // namespace udx
