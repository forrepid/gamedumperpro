// ----------------------------------------------------------------------------
// pdb.ts - MSVC PDB (Program Database) 7.0 symbol reader, pure TypeScript.
//
// Format implemented per LLVM (llvm/lib/DebugInfo/MSF +
// llvm/lib/DebugInfo/PDB/Native) and the microsoft/microsoft-pdb reference
// repo. All integers are little-endian.
//
// Layout recap:
//   SuperBlock (56 B @ 0) -> directory block list (@ BlockMapAddr) ->
//   directory (u32 stream count + per-stream sizes + per-stream block lists)
//   -> streams. Stream 1 = PDB info, stream 3 = DBI (+ debug header tail),
//   debug header slot 5 -> SectionHdr stream (COFF section headers).
//   CodeView records are walked in publics / globals / symrec streams.
//
// Robustness contract (never throws):
//   - MSF magic missing                       -> returns null
//   - structural corruption after the magic   -> { valid: false, error, ... }
//   - benign gaps (short info stream, absent optional streams, empty streams)
//                                             -> recorded in notes[]
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** MSF 7.0 superblock magic prefix (the full magic is 32 bytes). */
const MSF_MAGIC = "Microsoft C/C++ MSF 7.00";

/** Valid MSF block sizes (SuperBlock.BlockSize). */
const VALID_BLOCK_SIZES: number[] = [512, 1024, 2048, 4096, 8192, 16384, 32768];

// CodeView symbol record kinds (u16 kind after the 2-byte length field).
const S_PUB32 = 0x110e; // public symbol, u32 seg/off
const S_PUB32_ST = 0x1109; // public symbol, u16 seg/off (old ST format)
const S_UDT = 0x1108; // user-defined type, u32 type index
const S_UDT_ST = 0x1003; // user-defined type, u16 type index (old ST)
const S_GDATA32 = 0x110d; // global data
const S_LDATA32 = 0x110c; // local/static data

// Sanity caps.
const MAX_STREAMS = 0x10000; // directory stream count cap
const MAX_SYMBOLS = 20000; // symbol cap (truncation noted)
const MAX_UDT_NAMES = 2000; // UDT name cap (truncation noted)
const MAX_RECORDS = 500000; // CodeView walker record cap

/** Debug header: 11 u16 stream indices in this fixed order. */
const DBG_HEADER_ENTRIES = 11;
/** Slot of the SectionHdr (COFF section headers) stream in the debug header. */
const DBG_SECTION_HDR_SLOT = 5;
/** u16 stream-index sentinel: stream absent. */
const STREAM_ABSENT = 0xffff;
/** u32 stream-size sentinel: empty stream, no block entries in directory. */
const STREAM_SIZE_EMPTY = 0xffffffff;

const MACHINE_NAMES: Record<number, string> = {
  0x8664: "x64",
  0x014c: "x86",
  0xaa64: "ARM64",
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface PdbSection {
  name: string;
  rva: number;
  vsize: number;
}

export interface PdbSymbol {
  name: string;
  kind: "func" | "data";
  seg: number;
  off: number;
  rva?: number;
}

export interface PdbInfo {
  valid: boolean;
  /** PDB info stream version (e.g. 19990603 = VC70). */
  version: number;
  /** Unix-ish signature timestamp from the info stream. */
  signature: number;
  age: number;
  /** GUID rendered as 8-4-4-4-12 lowercase hex of the 16 raw bytes in order. */
  guid: string;
  /** From DBI MachineType: "x64" / "x86" / "ARM64", else "0x....". */
  machine: string;
  streamCount: number;
  sectionCount: number;
  funcCount: number;
  dataCount: number;
  udtCount: number;
  /** Publics (funcs + data) + globals data, deduped by name+seg+off. */
  symbols: PdbSymbol[];
  /** Unique S_UDT names (capped at 2000, truncation noted). */
  udtNames: string[];
  sections: PdbSection[];
  notes: string[];
  error?: string;
}

/**
 * Parse a PDB 7.0 (MSF container) image.
 *
 * Returns null ONLY when the MSF magic is missing. Otherwise never throws:
 * structural corruption yields { valid: false, error } plus every piece of
 * data that could still be recovered.
 */
export function parsePdb(buf: Buffer): PdbInfo | null {
  const info: PdbInfo = {
    valid: false,
    version: 0,
    signature: 0,
    age: 0,
    guid: "",
    machine: "",
    streamCount: 0,
    sectionCount: 0,
    funcCount: 0,
    dataCount: 0,
    udtCount: 0,
    symbols: [],
    udtNames: [],
    sections: [],
    notes: [],
  };

  if (!Buffer.isBuffer(buf) || buf.length < 32) return null;
  if (!buf.toString("latin1", 0, 32).startsWith(MSF_MAGIC)) return null;

  const msf = parseMsfContainer(buf, info);
  if (!msf) return info; // error already recorded, valid stays false
  info.streamCount = msf.streams.length;

  readInfoStream(msf, buf, info);

  const dbiStream = readStreamData(msf, buf, 3);
  let dbi: DbiHeader | null = null;
  if (dbiStream === null || dbiStream.length < 64) {
    setError(info, "DBI stream (3) missing or truncated");
  } else {
    dbi = readDbiHeader(dbiStream);
    info.machine = machineName(dbi.machineType);
  }

  const sectionHdrIndex = readDebugHeader(dbi, dbiStream, info);
  readSectionHeaders(msf, buf, sectionHdrIndex, info);
  harvestCodeView(msf, buf, dbi, info);

  info.valid = info.error === undefined;
  return info;
}

// ---------------------------------------------------------------------------
// Low-level bounds-checked readers
// ---------------------------------------------------------------------------

function rdU32(b: Buffer, off: number): number | null {
  return off >= 0 && off + 4 <= b.length ? b.readUInt32LE(off) : null;
}

/**
 * NUL-terminated string at `off`. Without maxBytes the NUL is mandatory
 * (returns null when missing = malformed record); with maxBytes the string
 * is bounded (used for the 8-byte COFF section names).
 */
function readNTS(b: Buffer, off: number, maxBytes?: number): string | null {
  if (off < 0 || off >= b.length) return null;
  const limit = maxBytes === undefined ? b.length : Math.min(b.length, off + maxBytes);
  for (let i = off; i < limit; i++) {
    if (b.readUInt8(i) === 0) return b.toString("latin1", off, i);
  }
  return maxBytes === undefined ? null : b.toString("latin1", off, limit);
}

/** 16 raw bytes at `off` -> lowercase hex grouped 8-4-4-4-12 (byte order kept). */
function guidToString(b: Buffer, off: number): string {
  const hx = (start: number, n: number): string => {
    let s = "";
    for (let i = 0; i < n; i++) s += b.readUInt8(off + start + i).toString(16).padStart(2, "0");
    return s;
  };
  return `${hx(0, 4)}-${hx(4, 2)}-${hx(6, 2)}-${hx(8, 2)}-${hx(10, 6)}`;
}

function machineName(machineType: number): string {
  return MACHINE_NAMES[machineType] ?? `0x${machineType.toString(16).padStart(4, "0")}`;
}

function setError(info: PdbInfo, msg: string): void {
  if (info.error === undefined) info.error = msg;
}

// ---------------------------------------------------------------------------
// MSF container
// ---------------------------------------------------------------------------

interface MsfStreamDef {
  size: number;
  blocks: number[];
}

interface MsfContainer {
  blockSize: number;
  numBlocks: number;
  streams: MsfStreamDef[];
}

/**
 * SuperBlock (56 B) -> directory block list (@ BlockMapAddr) -> directory.
 * Every field and block reference is validated; on any failure info.error is
 * set and null is returned (parsePdb then reports valid:false).
 */
function parseMsfContainer(buf: Buffer, info: PdbInfo): MsfContainer | null {
  if (buf.length < 56) {
    info.error = "file truncated: MSF superblock needs 56 bytes";
    return null;
  }
  const blockSize = buf.readUInt32LE(0x20);
  const freeBlockMapBlock = buf.readUInt32LE(0x24);
  const numBlocks = buf.readUInt32LE(0x28);
  const numDirectoryBytes = buf.readUInt32LE(0x2c);
  const blockMapAddr = buf.readUInt32LE(0x34);

  if (!VALID_BLOCK_SIZES.includes(blockSize)) {
    info.error = `invalid MSF block size ${blockSize}`;
    return null;
  }
  if (freeBlockMapBlock !== 1 && freeBlockMapBlock !== 2) {
    info.error = `invalid FreeBlockMapBlock ${freeBlockMapBlock} (must be 1 or 2)`;
    return null;
  }
  if (numBlocks < 1 || numBlocks * blockSize > buf.length) {
    info.error = `truncated file: ${numBlocks} blocks x ${blockSize} exceed ${buf.length} bytes`;
    return null;
  }
  if (numDirectoryBytes < 4) {
    info.error = "MSF directory truncated (NumDirectoryBytes < 4)";
    return null;
  }

  // Directory block list: ceil(NumDirectoryBytes / BlockSize) u32 entries.
  const dirBlockCount = Math.ceil(numDirectoryBytes / blockSize);
  if (blockMapAddr >= numBlocks || blockMapAddr * blockSize + dirBlockCount * 4 > buf.length) {
    info.error = "directory block list out of range";
    return null;
  }
  const dirBlocks: number[] = [];
  for (let i = 0; i < dirBlockCount; i++) {
    const b = buf.readUInt32LE(blockMapAddr * blockSize + i * 4);
    if (b >= numBlocks) {
      info.error = `directory block list entry ${i} references block ${b} >= NumBlocks`;
      return null;
    }
    dirBlocks.push(b);
  }

  // Concatenate the directory bytes from its blocks.
  const dir = Buffer.alloc(numDirectoryBytes);
  let got = 0;
  for (const b of dirBlocks) {
    const take = Math.min(blockSize, numDirectoryBytes - got);
    buf.copy(dir, got, b * blockSize, b * blockSize + take);
    got += take;
    if (got >= numDirectoryBytes) break;
  }

  // Directory: u32 NumStreams, NumStreams x u32 sizes, then per-stream block
  // lists (ceil(size/BlockSize) u32 entries each, in stream order). Size 0 or
  // 0xFFFFFFFF means empty stream -> no block entries.
  const numStreams = dir.readUInt32LE(0);
  if (numStreams > MAX_STREAMS || 4 + numStreams * 4 > numDirectoryBytes) {
    info.error = `invalid MSF stream count ${numStreams}`;
    return null;
  }
  let pos = 4;
  const sizes: number[] = [];
  for (let i = 0; i < numStreams; i++) {
    sizes.push(dir.readUInt32LE(pos));
    pos += 4;
  }
  const streams: MsfStreamDef[] = [];
  for (let i = 0; i < numStreams; i++) {
    const size = sizes[i];
    if (size !== 0 && size !== STREAM_SIZE_EMPTY && size > numBlocks * blockSize) {
      info.error = `stream ${i} size ${size} exceeds file capacity`;
      return null;
    }
    const count = size !== 0 && size !== STREAM_SIZE_EMPTY ? Math.ceil(size / blockSize) : 0;
    if (pos + count * 4 > numDirectoryBytes) {
      info.error = `MSF directory truncated: block list of stream ${i}`;
      return null;
    }
    const blocks: number[] = [];
    for (let j = 0; j < count; j++) {
      const b = dir.readUInt32LE(pos);
      pos += 4;
      if (b >= numBlocks) {
        info.error = `stream ${i} references block ${b} >= NumBlocks`;
        return null;
      }
      blocks.push(b);
    }
    streams.push({ size: size === STREAM_SIZE_EMPTY ? 0 : size, blocks });
  }

  return { blockSize, numBlocks, streams };
}

/** Concatenate a stream's blocks. Caller has validated block/file bounds. */
function readStreamData(msf: MsfContainer, buf: Buffer, index: number): Buffer | null {
  if (index < 0 || index >= msf.streams.length) return null;
  const s = msf.streams[index];
  if (s.size === 0 || s.blocks.length === 0) return Buffer.alloc(0);
  const out = Buffer.alloc(s.size);
  let got = 0;
  for (const b of s.blocks) {
    const off = b * msf.blockSize;
    if (off + msf.blockSize > buf.length) return null;
    const take = Math.min(msf.blockSize, s.size - got);
    buf.copy(out, got, off, off + take);
    got += take;
    if (got >= s.size) break;
  }
  return out;
}

// ---------------------------------------------------------------------------
// PDB streams
// ---------------------------------------------------------------------------

/** DBI stream header (64 bytes). */
interface DbiHeader {
  versionSignature: number;
  versionHeader: number;
  age: number;
  globalSymbolStreamIndex: number;
  buildNumber: number;
  publicSymbolStreamIndex: number;
  pdbDllVersion: number;
  symRecordStreamIndex: number;
  pdbDllRbld: number;
  modiSubstreamSize: number;
  secContrSubstreamSize: number;
  sectionMapSize: number;
  fileInfoSize: number;
  typeServerSize: number;
  mfcTypeServerIndex: number;
  optionalDbgHdrSize: number;
  ecSubstreamSize: number;
  flags: number;
  machineType: number;
  reserved: number;
}

function readDbiHeader(b: Buffer): DbiHeader {
  return {
    versionSignature: b.readInt32LE(0),
    versionHeader: b.readUInt32LE(4),
    age: b.readUInt32LE(8),
    globalSymbolStreamIndex: b.readUInt16LE(12),
    buildNumber: b.readUInt16LE(14),
    publicSymbolStreamIndex: b.readUInt16LE(16),
    pdbDllVersion: b.readUInt16LE(18),
    symRecordStreamIndex: b.readUInt16LE(20),
    pdbDllRbld: b.readUInt16LE(22),
    modiSubstreamSize: b.readInt32LE(24),
    secContrSubstreamSize: b.readInt32LE(28),
    sectionMapSize: b.readInt32LE(32),
    fileInfoSize: b.readInt32LE(36),
    typeServerSize: b.readInt32LE(40),
    mfcTypeServerIndex: b.readUInt32LE(44),
    optionalDbgHdrSize: b.readInt32LE(48),
    ecSubstreamSize: b.readInt32LE(52),
    flags: b.readUInt16LE(56),
    machineType: b.readUInt16LE(58),
    reserved: b.readUInt32LE(60),
  };
}

/** Stream 1: version / signature / age / GUID / names-stream index (defensive). */
function readInfoStream(msf: MsfContainer, buf: Buffer, info: PdbInfo): void {
  const stream = readStreamData(msf, buf, 1);
  if (stream === null) {
    setError(info, "PDB info stream (1) unreadable");
    return;
  }
  if (stream.length === 0) {
    info.notes.push("info stream (1) missing or empty");
    return;
  }
  const version = rdU32(stream, 0);
  if (version !== null) info.version = version;
  const signature = rdU32(stream, 4);
  if (signature !== null) info.signature = signature;
  const age = rdU32(stream, 8);
  if (age !== null) info.age = age;
  if (stream.length >= 28) {
    info.guid = guidToString(stream, 12);
  } else {
    info.notes.push("info stream (1) truncated: GUID incomplete");
  }
}

/**
 * DBI-tail debug header (OptionalDbgHdrSize bytes of u16 stream indices:
 * FPO, Exception, Fixup, OmapToSrc, OmapFromSrc, SectionHdr, TokenRidMap,
 * Xdata, Pdata, NewFPO, SectionHdrOrig; 0xFFFF = absent). The header sits at
 * DBI offset 64 + Modi + SecContr + SectionMap + FileInfo + TypeServer + EC.
 * Returns the SectionHdr stream index, or -1 when absent/unusable.
 */
function readDebugHeader(dbi: DbiHeader | null, dbiStream: Buffer | null, info: PdbInfo): number {
  if (dbi === null || dbiStream === null) return -1;
  if (dbi.optionalDbgHdrSize <= 0) {
    info.notes.push("no optional debug header");
    return -1;
  }
  const subSizes = [
    dbi.modiSubstreamSize,
    dbi.secContrSubstreamSize,
    dbi.sectionMapSize,
    dbi.fileInfoSize,
    dbi.typeServerSize,
    dbi.ecSubstreamSize,
  ];
  if (subSizes.some((s) => s < 0)) {
    setError(info, "negative DBI substream size");
    return -1;
  }
  const dbgOff =
    64 + subSizes[0] + subSizes[1] + subSizes[2] + subSizes[3] + subSizes[4] + subSizes[5];
  if (dbgOff + dbi.optionalDbgHdrSize > dbiStream.length) {
    setError(info, "DBI debug header out of bounds");
    return -1;
  }
  const slots = Math.min(DBG_HEADER_ENTRIES, Math.floor(dbi.optionalDbgHdrSize / 2));
  if (slots <= DBG_SECTION_HDR_SLOT) {
    info.notes.push("debug header too small: no SectionHdr slot");
    return -1;
  }
  const index = dbiStream.readUInt16LE(dbgOff + DBG_SECTION_HDR_SLOT * 2);
  if (index === STREAM_ABSENT) {
    info.notes.push("no section header stream (0xFFFF)");
    return -1;
  }
  return index;
}

/** Debug stream "SectionHdr": consecutive 40-byte COFF section headers. */
function readSectionHeaders(
  msf: MsfContainer,
  buf: Buffer,
  sectionHdrIndex: number,
  info: PdbInfo,
): void {
  if (sectionHdrIndex < 0) return;
  const stream = readStreamData(msf, buf, sectionHdrIndex);
  if (stream === null || stream.length < 40) {
    setError(info, `section header stream (${sectionHdrIndex}) missing or truncated`);
    return;
  }
  const count = Math.floor(stream.length / 40);
  for (let i = 0; i < count; i++) {
    const o = i * 40;
    info.sections.push({
      name: readNTS(stream, o, 8) ?? "",
      rva: stream.readUInt32LE(o + 12), // VirtualAddress
      vsize: stream.readUInt32LE(o + 8), // VirtualSize
    });
  }
  info.sectionCount = info.sections.length;
}

// ---------------------------------------------------------------------------
// CodeView records
// ---------------------------------------------------------------------------

/**
 * Shared CodeView record walker.
 *
 * Record layout: { u16 len; u16 kind; payload[len-2] } — `len` counts the
 * bytes AFTER the 2-byte length field (including the 2-byte kind field), so
 * the next record starts at pos + 2 + len. Stops when the stream ends, len < 2,
 * pos+2+len exceeds the stream (this naturally stops at the trailing hash
 * table of publics/globals streams) or after MAX_RECORDS records.
 * Unknown kinds are simply skipped (e.g. 0x1107 S_UDT_SC).
 */
function walkCodeView(stream: Buffer, visit: (kind: number, payload: Buffer) => void): number {
  let pos = 0;
  let records = 0;
  while (pos + 4 <= stream.length && records < MAX_RECORDS) {
    const len = stream.readUInt16LE(pos);
    if (len < 2) break;
    if (pos + 2 + len > stream.length) break;
    const kind = stream.readUInt16LE(pos + 2);
    visit(kind, stream.subarray(pos + 4, pos + 2 + len));
    pos += 2 + len;
    records++;
  }
  return records;
}

/** Publics + globals + symrec harvesting into info.symbols / info.udtNames. */
function harvestCodeView(
  msf: MsfContainer,
  buf: Buffer,
  dbi: DbiHeader | null,
  info: PdbInfo,
): void {
  if (dbi === null) return;

  // seg is 1-based into the COFF section header list.
  const resolveRva = (seg: number, off: number): number | undefined => {
    if (seg < 1 || seg > info.sections.length) return undefined;
    const sec = info.sections[seg - 1];
    return sec ? sec.rva + off : undefined;
  };

  const symbols: PdbSymbol[] = [];
  const seen = new Set<string>();
  let symbolsTruncated = false;
  const pushSymbol = (name: string, kind: PdbSymbol["kind"], seg: number, off: number): void => {
    if (symbolsTruncated) return;
    const key = `${name}|${seg}|${off}`;
    if (seen.has(key)) return;
    if (symbols.length >= MAX_SYMBOLS) {
      symbolsTruncated = true;
      return;
    }
    seen.add(key);
    symbols.push({ name, kind, seg, off, rva: resolveRva(seg, off) });
  };

  // Publics stream: S_PUB32 (u32 flags, u32 seg, u32 off, NTS name) and the
  // older S_PUB32_ST (u32 flags, u16 seg, u16 off, NTS name). flags bit0 =
  // code/function, bit1 = data; bit0 wins, otherwise reported as data.
  if (dbi.publicSymbolStreamIndex !== STREAM_ABSENT) {
    const stream = readStreamData(msf, buf, dbi.publicSymbolStreamIndex);
    if (stream === null || stream.length === 0) {
      info.notes.push("publics stream missing or empty");
    } else {
      walkCodeView(stream, (kind, payload) => {
        if (kind === S_PUB32 && payload.length >= 12) {
          const flags = payload.readUInt32LE(0);
          const seg = payload.readUInt32LE(4);
          const off = payload.readUInt32LE(8);
          const name = readNTS(payload, 12);
          if (name !== null) pushSymbol(name, (flags & 0x1) !== 0 ? "func" : "data", seg, off);
        } else if (kind === S_PUB32_ST && payload.length >= 8) {
          const flags = payload.readUInt32LE(0);
          const seg = payload.readUInt16LE(4);
          const off = payload.readUInt16LE(6);
          const name = readNTS(payload, 8);
          if (name !== null) pushSymbol(name, (flags & 0x1) !== 0 ? "func" : "data", seg, off);
        }
      });
    }
  }

  // Globals stream: S_GDATA32 / S_LDATA32 (u32 typeIndex, u16 seg, u32 off,
  // NTS name) -> data symbols.
  if (dbi.globalSymbolStreamIndex !== STREAM_ABSENT) {
    const stream = readStreamData(msf, buf, dbi.globalSymbolStreamIndex);
    if (stream === null || stream.length === 0) {
      info.notes.push("globals stream missing or empty");
    } else {
      walkCodeView(stream, (kind, payload) => {
        if ((kind === S_GDATA32 || kind === S_LDATA32) && payload.length >= 10) {
          const seg = payload.readUInt16LE(4);
          const off = payload.readUInt32LE(6);
          const name = readNTS(payload, 10);
          if (name !== null) pushSymbol(name, "data", seg, off);
        }
      });
    }
  }

  // Symbol record stream: S_UDT (u32 typeIndex, NTS name) / S_UDT_ST
  // (u16 typeIndex, NTS name) -> unique UDT names.
  if (dbi.symRecordStreamIndex !== STREAM_ABSENT) {
    const stream = readStreamData(msf, buf, dbi.symRecordStreamIndex);
    if (stream === null || stream.length === 0) {
      info.notes.push("symbol record stream missing or empty");
    } else {
      const udtSeen = new Set<string>();
      let udtsTruncated = false;
      walkCodeView(stream, (kind, payload) => {
        let name: string | null = null;
        if (kind === S_UDT && payload.length >= 4) name = readNTS(payload, 4);
        else if (kind === S_UDT_ST && payload.length >= 2) name = readNTS(payload, 2);
        if (name === null || name.length === 0 || udtSeen.has(name)) return;
        if (udtSeen.size >= MAX_UDT_NAMES) {
          udtsTruncated = true;
          return;
        }
        udtSeen.add(name);
      });
      info.udtNames = Array.from(udtSeen);
      if (udtsTruncated) info.notes.push(`udtNames truncated at cap ${MAX_UDT_NAMES}`);
    }
  }

  if (symbolsTruncated) info.notes.push(`symbols truncated at cap ${MAX_SYMBOLS}`);
  info.symbols = symbols;
  info.funcCount = symbols.reduce((n, s) => (s.kind === "func" ? n + 1 : n), 0);
  info.dataCount = symbols.reduce((n, s) => (s.kind === "data" ? n + 1 : n), 0);
  info.udtCount = info.udtNames.length;
}
