/**
 * BOLT12 bech32 encoding/decoding.
 *
 * BOLT12 uses bech32-style encoding WITHOUT a checksum:
 *   <hrp> "1" <bech32-data>
 *
 * The human-readable prefix (hrp) is one of: lno, lnr, lni, lnp.
 * The data part uses the standard bech32 alphabet to encode 5-bit groups
 * which are then converted to 8-bit bytes.
 *
 * BOLT12 also supports "+" continuation: a "+" followed by optional
 * whitespace can join multiple lines.
 */

const BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const ALPHABET_MAP: Record<string, number> = {};
for (let i = 0; i < BECH32_ALPHABET.length; i++) {
  ALPHABET_MAP[BECH32_ALPHABET[i]] = i;
}

export type Bolt12HRP = 'lno' | 'lnr' | 'lni' | 'lnp';

export interface Bolt12Decoded {
  hrp: Bolt12HRP;
  data: Uint8Array;
}

/**
 * Convert between bit groups (e.g., 5-bit to 8-bit).
 * Padding bits (if any) must be zero.
 */
function convertBits(
  data: number[],
  fromBits: number,
  toBits: number,
  strict: boolean = true
): number[] {
  let value = 0;
  let bits = 0;
  const maxV = (1 << toBits) - 1;
  const result: number[] = [];

  for (let i = 0; i < data.length; i++) {
    value = (value << fromBits) | data[i];
    bits += fromBits;

    while (bits >= toBits) {
      bits -= toBits;
      result.push((value >> bits) & maxV);
    }
  }

  if (strict) {
    // Check that padding bits are zero
    if (bits > 0) {
      const pad = (value << (toBits - bits)) & maxV;
      if (bits >= fromBits) {
        throw new Error('Excess padding in bech32 data');
      }
      if (pad !== 0) {
        throw new Error('Non-zero padding in bech32 data');
      }
    }
  } else {
    if (bits > 0) {
      result.push((value << (toBits - bits)) & maxV);
    }
  }

  return result;
}

/**
 * Convert 8-bit bytes to 5-bit bech32 groups.
 */
export function bytesToBech32(data: Uint8Array): number[] {
  const arr = Array.from(data);
  return convertBits(arr, 8, 5, false);
}

/**
 * Decode a BOLT12 string into its hrp and raw TLV bytes.
 */
export function decodeBolt12(input: string): Bolt12Decoded {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  // Handle "+" continuation: "+" optionally followed by whitespace joins parts
  let str = '';
  let i = 0;
  while (i < input.length) {
    if (input[i] === '+') {
      // The character before '+' must be a valid bech32 char
      if (i === 0) {
        throw new Error('Invalid "+" at start');
      }
      const prevChar = str[str.length - 1].toLowerCase();
      if (!(prevChar in ALPHABET_MAP)) {
        throw new Error('Invalid character before "+"');
      }
      i++; // skip '+'
      // skip optional whitespace (space, newline, carriage return)
      while (i < input.length && (input[i] === ' ' || input[i] === '\n' || input[i] === '\r')) {
        i++;
      }
      if (i >= input.length) {
        throw new Error('Invalid "+" at end');
      }
      // The character after whitespace must be a valid bech32 char
      const nextChar = input[i].toLowerCase();
      if (!(nextChar in ALPHABET_MAP)) {
        throw new Error('Invalid character after "+"');
      }
      continue;
    }
    if (input[i] === '\n' || input[i] === '\r') {
      i++;
      continue;
    }
    str += input[i];
    i++;
  }

  if (str.indexOf(' ') !== -1) {
    throw new Error('Invalid whitespace in bolt12 string');
  }

  // Must not be mixed case
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) {
    throw new Error('Mixed case in bolt12 string');
  }
  str = str.toLowerCase();

  // Must start with "ln"
  if (!str.startsWith('ln')) {
    throw new Error('Not a lightning payment request');
  }

  // Find separator "1"
  const sepIdx = str.lastIndexOf('1');
  if (sepIdx === -1) {
    throw new Error('No separator found');
  }

  const hrp = str.slice(0, sepIdx);
  const dataStr = str.slice(sepIdx + 1);

  if (!['lno', 'lnr', 'lni', 'lnp'].includes(hrp)) {
    throw new Error(`Unknown prefix: ${hrp}`);
  }

  if (dataStr.length === 0) {
    throw new Error('Empty data section');
  }

  // Decode bech32 characters to 5-bit values
  const words: number[] = [];
  for (let j = 0; j < dataStr.length; j++) {
    const c = dataStr[j];
    if (!(c in ALPHABET_MAP)) {
      throw new Error(`Invalid bech32 character: ${c}`);
    }
    words.push(ALPHABET_MAP[c]);
  }

  // Convert 5-bit to 8-bit
  const bytes = convertBits(words, 5, 8, true);

  return {
    hrp: hrp as Bolt12HRP,
    data: new Uint8Array(bytes),
  };
}

/**
 * Encode raw TLV bytes into a BOLT12 bech32 string.
 */
export function encodeBolt12(hrp: Bolt12HRP, data: Uint8Array): string {
  const words = bytesToBech32(data);
  let result = hrp + '1';
  for (const w of words) {
    result += BECH32_ALPHABET[w];
  }
  return result;
}
