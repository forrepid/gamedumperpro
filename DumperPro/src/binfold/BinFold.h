// ============================================================================
// DumperPro - BinFold.h
//
// Binary function fingerprinting + diff/match module ("binfold").
//
// Core algorithms ported from trumank/binfold (MIT License,
// Copyright (c) 2025 Truman Kilen - https://github.com/trumank/binfold):
//   * WARP-style function hashing: relocatable bytes are masked out of the
//     function body, the remainder is hashed into an RFC 4122 v5 GUID under
//     fixed domain namespaces (root namespace c1a7f83a-38a2-4bed-b6a3-
//     babc0df6860f, domains "function" / "basic_block" / "child_call" /
//     "parent_call" - same tags as binfold's hash.rs UuidV5 HashAlgo).
//   * Constraint model: a function is described by child_call / parent_call
//     constraints derived from its call graph neighbours' GUIDs.
//   * Iterative constraint-propagation matcher (lib.rs match loop): matches
//     seed the pool, every newly matched function contributes constraints to
//     its callers/callees, and a function whose constraint set identifies a
//     unique candidate is matched; repeat until fixpoint.
//
// Decoder-free adaptation (documented differences vs. upstream):
//   * binfold disassembles with iced-x86 to split basic blocks and mask every
//     RIP-relative/relocatable field. This port has NO disassembler: bodies
//     are split into fixed 64-byte segments and only direct call/jmp
//     displacement bytes (E8/E9 rel32, EB rel8) are masked. GUIDs are
//     structurally compatible (same scheme/namespace/masking intent) but NOT
//     byte-equal to upstream's basic-block GUIDs.
//   * binfold resolves SYMBOL NAMES from a .fold database built from binaries
//     with PDBs; the engine port matches two binaries DIRECTLY (reference ->
//     target) without a PDB, which is the workflow DumperPro users actually
//     have (two game versions, no symbols on either side).
//   * Function discovery: PE x64 via the .pdata exception directory, ELF64
//     via STT_FUNC symbols (symtab preferred, dynsym fallback), everything
//     else via a linear E8 rel32 call-target sweep (binfold's PE32 sweep.rs
//     equivalent, simplified).
//
// CLI: --bindiff <fileA> <fileB> [+ --bindiff-json <out>]
// ============================================================================
#pragma once
#include "../framework.h"

namespace dumper {
namespace binfold {

struct BfFunction {
    u64 addr = 0;          // image-relative address (RVA / st_value / file off)
    u32 size = 0;          // body bytes
    std::string guid;      // 36-char hyphenated UUIDv5 ("xxxxxxxx-....")
};

struct BfMatch {
    u64 addrA = 0, addrB = 0;
    u32 sizeA = 0, sizeB = 0;
    bool exact = false;    // exact = identical masked-body GUID
    double confidence = 0.0;  // inferred: matchedConstraints / totalConstraints
};

struct BfDiffResult {
    std::string formatA, formatB;    // human format labels (PE x64 .pdata / ELF64 symtab / raw)
    std::vector<BfFunction> funcsA, funcsB;
    std::vector<BfMatch> matches;
    std::vector<BfFunction> inserted;   // functions only in B
    std::vector<BfFunction> deleted;    // functions only in A
    double simFunctions = -1.0;         // 0..1; <0 when either side has no functions
    double simBytes = 0.0;              // 0..1 content-defined-chunking byte similarity
    size_t exactCount = 0, inferredCount = 0;
};

class BinFold {
public:
    // load a file fully into memory (cap 1 GiB, consistent with HexTool)
    static bool LoadFile(const fs::path& path, std::vector<u8>& data, std::string& err);

    // discover functions + compute WARP GUIDs. `format` gets a human label.
    static bool Analyze(const u8* data, size_t size, std::vector<BfFunction>& out,
                        std::string& format, std::string& err);

    // full reference->target diff (A = reference, B = target)
    static bool Diff(const u8* a, size_t sa, const u8* b, size_t sb,
                     BfDiffResult& out, std::string& err);

    // human-readable report (ends with a one-line Summary) + machine JSON
    static std::string BuildReport(const BfDiffResult& r,
                                   const std::string& nameA, const std::string& nameB);
    static std::string BuildJson(const BfDiffResult& r,
                                 const std::string& nameA, const std::string& nameB);
};

} // namespace binfold
} // namespace dumper
