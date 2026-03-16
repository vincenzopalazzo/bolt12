/**
 * BOLT12 Payer Proof (experimental, PR #1295).
 *
 * A payer proof is a proof of invoice payment, encoded with the "lnp" prefix.
 * It contains a subset of the invoice's TLV fields, allowing the payer to
 * prove they paid a specific invoice while selectively disclosing only
 * certain fields for privacy.
 *
 * New TLV types:
 *   242 - preimage           (32-byte payment preimage)
 *   244 - omitted_tlvs       (array of bigsize marker numbers)
 *   246 - missing_hashes     (array of sha256 hashes for merkle reconstruction)
 *   248 - leaf_hashes        (array of sha256 nonce hashes for included TLVs)
 *   250 - payer_signature    (bip340sig + optional UTF-8 note)
 */

import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';
import type { TlvRecord } from './tlv.js';
import { readBigSize, writeBigSize } from './bigsize.js';
import { taggedHash } from './merkle.js';
import { compareBytes, isSignatureType, toHex } from './utils.js';

const encoder = new TextEncoder();

// Payer proof specific TLV types
export const PP_PREIMAGE = 242n;
export const PP_OMITTED_TLVS = 244n;
export const PP_MISSING_HASHES = 246n;
export const PP_LEAF_HASHES = 248n;
export const PP_PAYER_SIGNATURE = 250n;

// Invoice field types needed for validation
const INVREQ_METADATA = 0n;
const INVREQ_PAYER_ID = 88n;
const INVOICE_PAYMENT_HASH = 168n;
const INVOICE_NODE_ID = 176n;
const SIGNATURE = 240n;

/**
 * Parse an array of BigSize values from a byte buffer.
 */
function parseBigSizeArray(data: Uint8Array): bigint[] {
  const result: bigint[] = [];
  let offset = 0;
  while (offset < data.length) {
    const { value, bytesRead } = readBigSize(data, offset);
    result.push(value);
    offset += bytesRead;
  }
  return result;
}

/**
 * Parse an array of 32-byte SHA256 hashes from a byte buffer.
 */
function parseSha256Array(data: Uint8Array): Uint8Array[] {
  if (data.length % 32 !== 0) {
    throw new Error('Hash array length must be a multiple of 32');
  }
  const result: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += 32) {
    result.push(data.slice(i, i + 32));
  }
  return result;
}

/**
 * Compute the nonce hash for a TLV field.
 * nonce = H("LnNonce" || TLV0_bytes, type_as_bigsize)
 *
 * Note: TLV0 is the invreq_metadata, which is NOT included in the payer proof
 * (it's secret). The nonce hashes are pre-computed and provided in leaf_hashes.
 */

/**
 * Compute a Merkle branch hash from two child hashes.
 */
function branchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  const tag = encoder.encode('LnBranch');
  const [smaller, larger] = compareBytes(a, b) < 0 ? [a, b] : [b, a];
  return taggedHash(tag, concatBytes(smaller, larger));
}

/**
 * Compute the leaf+nonce branch for a given TLV record and its nonce hash.
 */
function leafBranch(tlvBytes: Uint8Array, nonceHash: Uint8Array): Uint8Array {
  const leafTag = encoder.encode('LnLeaf');
  const leaf = taggedHash(leafTag, tlvBytes);
  return branchHash(leaf, nonceHash);
}

/**
 * Serialize a TLV record to wire bytes.
 */
function tlvToBytes(record: TlvRecord): Uint8Array {
  const typeBytes = writeBigSize(record.type);
  const lengthBytes = writeBigSize(record.length);
  return concatBytes(typeBytes, lengthBytes, record.value);
}

export interface PayerProofFields {
  /** Included TLV records (non-signature, non-payer-proof-specific) */
  includedRecords: TlvRecord[];
  /** The invoice signature (type 240) */
  signature: Uint8Array;
  /** Payment preimage (type 242, 32 bytes) */
  preimage: Uint8Array | undefined;
  /** Marker numbers for omitted TLVs (type 244) */
  omittedTlvs: bigint[];
  /** Missing merkle branch hashes (type 246) */
  missingHashes: Uint8Array[];
  /** Nonce hashes for included non-signature TLVs (type 248) */
  leafHashes: Uint8Array[];
  /** Payer signature (type 250) */
  payerSignature: Uint8Array;
  /** Optional note from payer_signature (type 250) */
  payerNote: string;
  /** invoice_payment_hash for preimage verification */
  invoicePaymentHash: Uint8Array;
  /** invoice_node_id for signature verification */
  invoiceNodeId: Uint8Array;
  /** invreq_payer_id for payer_signature verification */
  payerId: Uint8Array;
}

/**
 * Parse and validate a payer proof's TLV records.
 */
export function parsePayerProof(records: TlvRecord[]): PayerProofFields {
  const includedRecords: TlvRecord[] = [];
  let signature: Uint8Array | null = null;
  let preimage: Uint8Array | null = null;
  let omittedTlvsRaw: Uint8Array | null = null;
  let missingHashesRaw: Uint8Array | null = null;
  let leafHashesRaw: Uint8Array | null = null;
  let payerSignatureRaw: Uint8Array | null = null;
  let invoicePaymentHash: Uint8Array | null = null;
  let invoiceNodeId: Uint8Array | null = null;
  let payerId: Uint8Array | null = null;

  for (const record of records) {
    const type = record.type;

    // invreq_metadata (type 0) MUST NOT be included
    if (type === INVREQ_METADATA) {
      throw new Error('Payer proof MUST NOT include invreq_metadata (type 0)');
    }

    // Track required fields
    if (type === INVREQ_PAYER_ID) {
      payerId = record.value;
    } else if (type === INVOICE_PAYMENT_HASH) {
      invoicePaymentHash = record.value;
    } else if (type === INVOICE_NODE_ID) {
      invoiceNodeId = record.value;
    }

    // Handle payer-proof-specific fields
    if (type === SIGNATURE) {
      if (record.value.length !== 64) {
        throw new Error('Invalid signature: expected 64 bytes');
      }
      signature = record.value;
    } else if (type === PP_PREIMAGE) {
      if (record.value.length !== 32) {
        throw new Error('Invalid preimage: expected 32 bytes');
      }
      preimage = record.value;
    } else if (type === PP_OMITTED_TLVS) {
      omittedTlvsRaw = record.value;
    } else if (type === PP_MISSING_HASHES) {
      missingHashesRaw = record.value;
    } else if (type === PP_LEAF_HASHES) {
      leafHashesRaw = record.value;
    } else if (type === PP_PAYER_SIGNATURE) {
      if (record.value.length < 64) {
        throw new Error('Invalid payer_signature: expected at least 64 bytes');
      }
      payerSignatureRaw = record.value;
    } else if (!isSignatureType(type)) {
      // Non-signature, non-payer-proof field -> included invoice record
      includedRecords.push(record);
    }
  }

  // Required fields check
  if (!payerId) throw new Error('Missing invreq_payer_id');
  if (!invoicePaymentHash) throw new Error('Missing invoice_payment_hash');
  if (!invoiceNodeId) throw new Error('Missing invoice_node_id');
  if (!signature) throw new Error('Missing signature');
  if (!payerSignatureRaw) throw new Error('Missing payer_signature');

  // Parse omitted_tlvs
  const omittedTlvs = omittedTlvsRaw ? parseBigSizeArray(omittedTlvsRaw) : [];

  // Validate omitted_tlvs
  validateOmittedTlvs(omittedTlvs, includedRecords);

  // Parse missing_hashes
  const missingHashes = missingHashesRaw ? parseSha256Array(missingHashesRaw) : [];

  // Parse leaf_hashes
  const leafHashes = leafHashesRaw ? parseSha256Array(leafHashesRaw) : [];

  // Validate leaf_hashes count matches included non-signature TLVs
  if (leafHashes.length !== includedRecords.length) {
    throw new Error(
      `leaf_hashes count (${leafHashes.length}) must match included non-signature TLV count (${includedRecords.length})`
    );
  }

  // Validate preimage matches payment hash
  if (preimage) {
    const computedHash = sha256(preimage);
    if (toHex(computedHash) !== toHex(invoicePaymentHash)) {
      throw new Error('SHA256(preimage) does not match invoice_payment_hash');
    }
  }

  // Extract payer signature and optional note
  const payerSignature = payerSignatureRaw.slice(0, 64);
  const payerNoteBytes = payerSignatureRaw.slice(64);
  let payerNote = '';
  if (payerNoteBytes.length > 0) {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
      payerNote = decoder.decode(payerNoteBytes);
    } catch {
      throw new Error('Invalid UTF-8 in payer_signature note');
    }
  }

  return {
    includedRecords,
    signature,
    preimage: preimage || undefined,
    omittedTlvs,
    missingHashes,
    leafHashes,
    payerSignature,
    payerNote,
    invoicePaymentHash,
    invoiceNodeId,
    payerId,
  };
}

/**
 * Validate the omitted_tlvs array.
 */
function validateOmittedTlvs(omittedTlvs: bigint[], includedRecords: TlvRecord[]): void {
  // Must be in strict ascending order (no duplicates)
  for (let i = 1; i < omittedTlvs.length; i++) {
    if (omittedTlvs[i] <= omittedTlvs[i - 1]) {
      throw new Error('omitted_tlvs must be in strict ascending order');
    }
  }

  // Must not contain 0
  if (omittedTlvs.includes(0n)) {
    throw new Error('omitted_tlvs must not contain 0');
  }

  // Must not contain signature type numbers (240-1000)
  for (const marker of omittedTlvs) {
    if (isSignatureType(marker)) {
      throw new Error(`omitted_tlvs must not contain signature type number ${marker}`);
    }
  }

  // Must not contain the type number of any included TLV field
  const includedTypes = new Set(includedRecords.map(r => r.type));
  for (const marker of omittedTlvs) {
    if (includedTypes.has(marker)) {
      throw new Error(`omitted_tlvs must not contain included TLV type ${marker}`);
    }
  }

  // Must not contain more than one number larger than the largest included non-signature TLV
  if (includedRecords.length > 0) {
    const maxIncluded = includedRecords[includedRecords.length - 1].type;
    const largerMarkers = omittedTlvs.filter(m => m > maxIncluded);
    if (largerMarkers.length > 1) {
      throw new Error('omitted_tlvs must not contain more than one marker larger than the largest included TLV');
    }
  }
}

/**
 * Reconstruct the Merkle root from a payer proof.
 *
 * This takes the included TLV records with their nonce hashes (leaf_hashes),
 * the omitted TLV markers, and the missing branch hashes, and reconstructs
 * the full Merkle tree to verify the invoice signature.
 *
 * The algorithm works by building the Merkle tree from left to right:
 * - For included fields, compute the leaf+nonce branch using the provided nonce hash.
 * - For omitted fields, pull a hash from missing_hashes.
 * - Combine adjacent nodes into parent branches.
 */
export function reconstructMerkleRoot(proof: PayerProofFields): Uint8Array {
  // Build the ordered list of all nodes (included and omitted)
  // by interleaving included records and omitted markers
  interface MerkleNode {
    type: 'included' | 'omitted';
    hash?: Uint8Array;
    record?: TlvRecord;
    nonceHash?: Uint8Array;
  }

  const allNodes: MerkleNode[] = [];
  let includedIdx = 0;
  let omittedIdx = 0;

  // Merge included records and omitted markers in ascending order
  // The markers represent positions of omitted fields
  while (includedIdx < proof.includedRecords.length || omittedIdx < proof.omittedTlvs.length) {
    const includedType = includedIdx < proof.includedRecords.length
      ? proof.includedRecords[includedIdx].type : BigInt(Number.MAX_SAFE_INTEGER);
    const omittedMarker = omittedIdx < proof.omittedTlvs.length
      ? proof.omittedTlvs[omittedIdx] : BigInt(Number.MAX_SAFE_INTEGER);

    if (includedType < omittedMarker) {
      allNodes.push({
        type: 'included',
        record: proof.includedRecords[includedIdx],
        nonceHash: proof.leafHashes[includedIdx],
      });
      includedIdx++;
    } else {
      allNodes.push({ type: 'omitted' });
      omittedIdx++;
    }
  }

  // Now build the Merkle tree
  let missingIdx = 0;

  // Compute leaf branches for included nodes
  let nodes: Uint8Array[] = [];
  for (const node of allNodes) {
    if (node.type === 'included' && node.record && node.nonceHash) {
      const tlvBytes = tlvToBytes(node.record);
      nodes.push(leafBranch(tlvBytes, node.nonceHash));
    } else {
      // Omitted node - will be filled from missing_hashes during tree construction
      // Use a placeholder
      nodes.push(new Uint8Array(0));
    }
  }

  // Build tree bottom-up, pulling missing_hashes for omitted subtrees
  while (nodes.length > 1) {
    const parents: Uint8Array[] = [];
    let i = 0;
    while (i < nodes.length) {
      if (i + 1 < nodes.length) {
        const left = nodes[i];
        const right = nodes[i + 1];
        const leftEmpty = left.length === 0;
        const rightEmpty = right.length === 0;

        if (leftEmpty && rightEmpty) {
          // Both omitted - combine into single omitted node
          parents.push(new Uint8Array(0));
        } else if (leftEmpty) {
          // Left omitted, right present - pull from missing_hashes
          if (missingIdx >= proof.missingHashes.length) {
            throw new Error('Not enough missing_hashes to reconstruct merkle tree');
          }
          parents.push(branchHash(proof.missingHashes[missingIdx++], right));
        } else if (rightEmpty) {
          // Right omitted, left present - pull from missing_hashes
          if (missingIdx >= proof.missingHashes.length) {
            throw new Error('Not enough missing_hashes to reconstruct merkle tree');
          }
          parents.push(branchHash(left, proof.missingHashes[missingIdx++]));
        } else {
          // Both present
          parents.push(branchHash(left, right));
        }
        i += 2;
      } else {
        // Odd node promoted
        parents.push(nodes[i]);
        i += 1;
      }
    }
    nodes = parents;
  }

  if (missingIdx !== proof.missingHashes.length) {
    throw new Error(
      `Excess missing_hashes: used ${missingIdx} of ${proof.missingHashes.length}`
    );
  }

  if (nodes.length === 0 || nodes[0].length === 0) {
    throw new Error('Failed to reconstruct merkle root');
  }

  return nodes[0];
}

/**
 * Verify a payer proof's signatures.
 *
 * 1. Reconstruct the Merkle root from the proof data.
 * 2. Verify the invoice signature using invoice_node_id.
 * 3. Verify the payer_signature using invreq_payer_id.
 */
export function verifyPayerProof(proof: PayerProofFields): {
  valid: boolean;
  merkleRoot: Uint8Array;
  error?: string;
} {
  try {
    const merkleRoot = reconstructMerkleRoot(proof);

    // Verify invoice signature: tag = "lightninginvoicesignature"
    const invoiceSigTag = encoder.encode('lightninginvoicesignature');
    const invoiceSigMsg = taggedHash(invoiceSigTag, merkleRoot);
    // invoice_node_id is a compressed point (33 bytes), schnorr uses x-only (32 bytes)
    const nodeIdX = proof.invoiceNodeId.length === 33
      ? proof.invoiceNodeId.slice(1)
      : proof.invoiceNodeId;

    const invoiceSigValid = schnorr.verify(proof.signature, invoiceSigMsg, nodeIdX);
    if (!invoiceSigValid) {
      return { valid: false, merkleRoot, error: 'Invalid invoice signature' };
    }

    // Verify payer_signature: SIG(tag, msg, key)
    // tag = "lightningpayer_proofpayer_signature"
    // msg = SHA256(note || merkle-root)
    const noteBytes = encoder.encode(proof.payerNote);
    const payerRawMsg = sha256(concatBytes(noteBytes, merkleRoot));
    const payerSigTag = encoder.encode('lightningpayer_proofpayer_signature');
    const payerMsg = taggedHash(payerSigTag, payerRawMsg);
    const payerIdX = proof.payerId.length === 33
      ? proof.payerId.slice(1)
      : proof.payerId;

    const payerSigValid = schnorr.verify(proof.payerSignature, payerMsg, payerIdX);
    if (!payerSigValid) {
      return { valid: false, merkleRoot, error: 'Invalid payer signature' };
    }

    return { valid: true, merkleRoot };
  } catch (e: any) {
    return { valid: false, merkleRoot: new Uint8Array(32), error: e.message };
  }
}
