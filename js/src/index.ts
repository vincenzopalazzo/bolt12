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
/**
 * @deprecated Use `extractGeneratedOfferFields` and `GeneratedOfferFields` from
 * the auto-generated module instead. These hand-written exports use non-spec
 * field names (e.g. `description` instead of `offer_description`) and only
 * cover offers — the generated module covers all BOLT12 message types.
 */
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

// Auto-generated types and extractors from BOLT12 spec CSV
export {
  // Offer
  type OfferFields as GeneratedOfferFields,
  extractOfferFields as extractGeneratedOfferFields,
  KNOWN_OFFER_TYPES,
  OFFER_TLV_NAMES,
  // Invoice request
  type InvoiceRequestFields,
  extractInvoiceRequestFields,
  KNOWN_INVOICE_REQUEST_TYPES,
  INVOICE_REQUEST_TLV_NAMES,
  // Invoice
  type InvoiceFields,
  extractInvoiceFields,
  KNOWN_INVOICE_TYPES,
  INVOICE_TLV_NAMES,
  // Invoice error
  type InvoiceErrorFields,
  extractInvoiceErrorFields,
  KNOWN_INVOICE_ERROR_TYPES,
  INVOICE_ERROR_TLV_NAMES,
  // Payer proof
  type PayerProofFields as GeneratedPayerProofFields,
  extractPayerProofFields,
  KNOWN_PAYER_PROOF_TYPES,
  PAYER_PROOF_TLV_NAMES,
  // Subtypes
  type BlindedPayinfo,
  type FallbackAddress,
  // Constants (all)
  OFFER_CHAINS, OFFER_METADATA, OFFER_CURRENCY, OFFER_AMOUNT,
  OFFER_DESCRIPTION, OFFER_FEATURES, OFFER_ABSOLUTE_EXPIRY,
  OFFER_PATHS, OFFER_ISSUER, OFFER_QUANTITY_MAX, OFFER_ISSUER_ID,
  INVREQ_METADATA, INVREQ_CHAIN, INVREQ_AMOUNT, INVREQ_FEATURES,
  INVREQ_QUANTITY, INVREQ_PAYER_ID, INVREQ_PAYER_NOTE, INVREQ_PATHS,
  INVREQ_BIP_353_NAME, SIGNATURE,
  INVOICE_PATHS, INVOICE_BLINDEDPAY, INVOICE_CREATED_AT,
  INVOICE_RELATIVE_EXPIRY, INVOICE_PAYMENT_HASH, INVOICE_AMOUNT,
  INVOICE_FALLBACKS, INVOICE_FEATURES, INVOICE_NODE_ID,
  PROOF_SIGNATURE, PROOF_PREIMAGE, PROOF_OMITTED_TLVS,
  PROOF_MISSING_HASHES, PROOF_LEAF_HASHES, PROOF_NOTE,
} from './generated.js';

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
