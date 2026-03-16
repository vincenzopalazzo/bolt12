/**
 * BigSize encoding/decoding as defined in BOLT 1.
 *
 * BigSize is a variable-length unsigned integer encoding:
 *   0x00-0xfc:       1 byte (value itself)
 *   0xfd + u16:      3 bytes (values 0xfd-0xffff)
 *   0xfe + u32:      5 bytes (values 0x10000-0xffffffff)
 *   0xff + u64:      9 bytes (values 0x100000000+)
 */

export interface BigSizeResult {
  value: bigint;
  bytesRead: number;
}

/**
 * Read a BigSize value from a buffer at the given offset.
 */
export function readBigSize(buf: Uint8Array, offset: number = 0): BigSizeResult {
  if (offset >= buf.length) {
    throw new Error('Truncated bigsize: no data');
  }

  const first = buf[offset];

  if (first < 0xfd) {
    return { value: BigInt(first), bytesRead: 1 };
  }

  if (first === 0xfd) {
    if (offset + 3 > buf.length) {
      throw new Error('Truncated bigsize: expected 2 more bytes');
    }
    const val = (buf[offset + 1] << 8) | buf[offset + 2];
    if (val < 0xfd) {
      throw new Error('Non-minimal bigsize encoding');
    }
    return { value: BigInt(val), bytesRead: 3 };
  }

  if (first === 0xfe) {
    if (offset + 5 > buf.length) {
      throw new Error('Truncated bigsize: expected 4 more bytes');
    }
    const dv = new DataView(buf.buffer, buf.byteOffset + offset + 1, 4);
    const val = dv.getUint32(0);
    if (val < 0x10000) {
      throw new Error('Non-minimal bigsize encoding');
    }
    return { value: BigInt(val), bytesRead: 5 };
  }

  // first === 0xff
  if (offset + 9 > buf.length) {
    throw new Error('Truncated bigsize: expected 8 more bytes');
  }
  const dv = new DataView(buf.buffer, buf.byteOffset + offset + 1, 8);
  const hi = BigInt(dv.getUint32(0)) << 32n;
  const lo = BigInt(dv.getUint32(4));
  const val = hi | lo;
  if (val < 0x100000000n) {
    throw new Error('Non-minimal bigsize encoding');
  }
  return { value: val, bytesRead: 9 };
}

/**
 * Encode a BigSize value into bytes.
 */
export function writeBigSize(value: bigint): Uint8Array {
  if (value < 0xfdn) {
    return new Uint8Array([Number(value)]);
  }

  if (value <= 0xffffn) {
    const buf = new Uint8Array(3);
    buf[0] = 0xfd;
    buf[1] = Number((value >> 8n) & 0xffn);
    buf[2] = Number(value & 0xffn);
    return buf;
  }

  if (value <= 0xffffffffn) {
    const buf = new Uint8Array(5);
    buf[0] = 0xfe;
    const dv = new DataView(buf.buffer, 1, 4);
    dv.setUint32(0, Number(value));
    return buf;
  }

  const buf = new Uint8Array(9);
  buf[0] = 0xff;
  const dv = new DataView(buf.buffer, 1, 8);
  dv.setUint32(0, Number(value >> 32n));
  dv.setUint32(4, Number(value & 0xffffffffn));
  return buf;
}
