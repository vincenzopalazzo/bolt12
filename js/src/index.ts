/**
 * bolt12-decoder: Pure JS/TS BOLT12 implementation.
 *
 * Supports decoding and validating BOLT12 offers, invoice requests,
 * and invoices using only pure JavaScript dependencies:
 *   - @noble/curves for secp256k1/schnorr
 *   - @noble/hashes for SHA256
 */

export { decodeBolt12, encodeBolt12 } from './bech32.js';
export { readBigSize, writeBigSize } from './bigsize.js';
export { parseTlvStream, type TlvRecord } from './tlv.js';
export { computeMerkleRoot, taggedHash, verifySignature } from './merkle.js';
export { validateOffer } from './offer.js';

import { decodeBolt12, type Bolt12HRP } from './bech32.js';
import { parseTlvStream, type TlvRecord } from './tlv.js';
import { computeMerkleRoot, verifySignature } from './merkle.js';
import { validateOffer } from './offer.js';

export interface DecodedOffer {
  hrp: Bolt12HRP;
  records: TlvRecord[];
  merkleRoot: Uint8Array;
}

/**
 * Decode and validate a BOLT12 offer string.
 */
export function decodeOffer(bolt12String: string): DecodedOffer {
  const { hrp, data } = decodeBolt12(bolt12String);

  if (hrp !== 'lno') {
    throw new Error(`Expected offer (lno), got ${hrp}`);
  }

  const records = parseTlvStream(data);

  // Validate offer semantics
  validateOffer(records);

  // Compute offer_id (merkle root of all TLVs)
  const merkleRoot = computeMerkleRoot(records);

  return { hrp, records, merkleRoot };
}
