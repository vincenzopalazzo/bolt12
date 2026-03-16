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
export {
  extractOfferFields,
  type OfferFields,
  type Chain,
} from './fields.js';
export {
  parsePayerProof,
  reconstructMerkleRoot,
  verifyPayerProof,
  createPayerProof,
  type PayerProofFields,
  type CreatePayerProofParams,
  type CreatePayerProofResult,
} from './payer_proof.js';

import { decodeBolt12, type Bolt12HRP } from './bech32.js';
import { parseTlvStream, type TlvRecord } from './tlv.js';
import { computeMerkleRoot, verifySignature } from './merkle.js';
import { validateOffer } from './offer.js';
import { extractOfferFields, type OfferFields } from './fields.js';
import { parsePayerProof, createPayerProof, type PayerProofFields, type CreatePayerProofParams, type CreatePayerProofResult } from './payer_proof.js';

export interface DecodedOffer extends OfferFields {
  hrp: Bolt12HRP;
  offer_id: Uint8Array;
}

/**
 * Decode and validate a BOLT12 offer string.
 *
 * Returns typed fields directly:
 *   const { description, amount, issuer_id, offer_id } = decodeOffer(str);
 */
export function decodeOffer(bolt12String: string): DecodedOffer {
  const { hrp, data } = decodeBolt12(bolt12String);

  if (hrp !== 'lno') {
    throw new Error(`Expected offer (lno), got ${hrp}`);
  }

  const records = parseTlvStream(data);

  // Validate offer semantics
  validateOffer(records);

  // Extract typed fields
  const fields = extractOfferFields(records);

  // Compute offer_id (merkle root of all TLVs)
  const offer_id = computeMerkleRoot(records);

  return { ...fields, hrp, offer_id };
}

export interface DecodedPayerProof {
  hrp: Bolt12HRP;
  records: TlvRecord[];
  proof: PayerProofFields;
}

/**
 * Decode and validate a BOLT12 payer proof string (experimental, PR #1295).
 */
export function decodePayerProof(bolt12String: string): DecodedPayerProof {
  const { hrp, data } = decodeBolt12(bolt12String);

  if (hrp !== 'lnp') {
    throw new Error(`Expected payer proof (lnp), got ${hrp}`);
  }

  const records = parseTlvStream(data);
  const proof = parsePayerProof(records);

  return { hrp, records, proof };
}
