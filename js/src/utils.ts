/**
 * Shared utility functions for BOLT12 modules.
 */

/** Read a truncated big-endian unsigned integer from bytes. Empty = 0. */
export function readTruncatedUint(data: Uint8Array): bigint {
  if (data.length === 0) return 0n;
  let val = 0n;
  for (let i = 0; i < data.length; i++) {
    val = (val << 8n) | BigInt(data[i]);
  }
  return val;
}

/** Convert bytes to lowercase hex string. */
export function toHex(buf: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** Compare two byte arrays lexicographically. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}
