// Minimal ZIP (STORE method) writer - zero dependencies.
// Produces a valid .zip archive from in-memory buffers.

const CRC_TABLE: number[] = (() => {
  const t: number[] = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(d: Date): { time: number; date: number } {
  const time =
    (d.getHours() << 11) | (d.getMinutes() << 5) | (Math.floor(d.getSeconds() / 2) & 0x1f);
  const date =
    ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

export interface ZipEntry {
  path: string; // archive-internal path (forward slashes)
  data: Buffer;
}

export function createZip(entries: ZipEntry[]): Buffer {
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  const { time, date } = dosDateTime(new Date());
  let offset = 0;

  const writeU16 = (v: number) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(v & 0xffff, 0);
    return b;
  };
  const writeU32 = (v: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v >>> 0, 0);
    return b;
  };

  for (const e of entries) {
    const nameBuf = Buffer.from(e.path.replace(/\\/g, "/"), "utf8");
    const crc = crc32(e.data);

    // Local file header
    const local = Buffer.concat([
      writeU32(0x04034b50),
      writeU16(20), // version needed
      writeU16(0x0800), // flags: UTF-8 names
      writeU16(0), // method: store
      writeU16(time),
      writeU16(date),
      writeU32(crc),
      writeU32(e.data.length),
      writeU32(e.data.length),
      writeU16(nameBuf.length),
      writeU16(0), // extra len
      nameBuf,
      e.data,
    ]);
    chunks.push(local);

    // Central directory record
    central.push(
      Buffer.concat([
        writeU32(0x02014b50),
        writeU16(20), // version made by
        writeU16(20), // version needed
        writeU16(0x0800),
        writeU16(0),
        writeU16(time),
        writeU16(date),
        writeU32(crc),
        writeU32(e.data.length),
        writeU32(e.data.length),
        writeU16(nameBuf.length),
        writeU16(0),
        writeU16(0),
        writeU16(0),
        writeU16(0),
        writeU32(0),
        writeU32(offset),
        nameBuf,
      ]),
    );

    offset += local.length;
  }

  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.concat([
    writeU32(0x06054b50),
    writeU16(0),
    writeU16(0),
    writeU16(entries.length),
    writeU16(entries.length),
    writeU32(centralBuf.length),
    writeU32(offset),
    writeU16(0),
  ]);

  return Buffer.concat([...chunks, centralBuf, eocd]);
}
