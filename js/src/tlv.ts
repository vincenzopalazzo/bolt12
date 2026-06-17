/**
 * TLV (Type-Length-Value) stream parsing for BOLT12.
 *
 * A TLV stream is a sequence of records, each consisting of:
 *   - type: BigSize
 *   - length: BigSize
 *   - value: `length` bytes
 *
 * Records MUST appear in strictly ascending type order.
 */

import { readBigSize, writeBigSize } from './bigsize.js';

export interface TlvRecord {
  type: bigint;
  length: bigint;
  value: Uint8Array;
}

/**
 * Parse a TLV stream from raw bytes.
 * Returns an array of TLV records.
 * Throws if types are not in ascending order.
 */
export function parseTlvStream(data: Uint8Array): TlvRecord[] {
  const records: TlvRecord[] = [];
  let offset = 0;
  let lastType = -1n;

  while (offset < data.length) {
    // Read type
    const typeResult = readBigSize(data, offset);
    offset += typeResult.bytesRead;
    const tlvType = typeResult.value;

    // Check ascending order
    if (tlvType <= lastType) {
      throw new Error('TLV fields not in ascending order');
    }
    lastType = tlvType;

    // Read length
    if (offset >= data.length) {
      throw new Error('Truncated TLV: missing length');
    }
    const lengthResult = readBigSize(data, offset);
    offset += lengthResult.bytesRead;
    const tlvLength = lengthResult.value;

    // Read value
    const len = Number(tlvLength);
    if (offset + len > data.length) {
      throw new Error('Truncated TLV: value extends beyond data');
    }
    const value = data.slice(offset, offset + len);
    offset += len;

    records.push({ type: tlvType, length: tlvLength, value });
  }

  return records;
}

/**
 * Serialize a TLV record to bytes (type + length + value).
 */
export function serializeTlvRecord(record: TlvRecord): Uint8Array {
  const typeBytes = writeBigSize(record.type);
  const lengthBytes = writeBigSize(record.length);
  const result = new Uint8Array(typeBytes.length + lengthBytes.length + record.value.length);
  result.set(typeBytes, 0);
  result.set(lengthBytes, typeBytes.length);
  result.set(record.value, typeBytes.length + lengthBytes.length);
  return result;
}
