/**
 * BOLT12 Payer Proof (experimental, PR #1295).
 *
 * A payer proof is a proof of invoice payment, encoded with the "lnp" prefix.
 * It contains a subset of the invoice's TLV fields, allowing the payer to
 * prove they paid a specific invoice while selectively disclosing only
 * certain fields for privacy.
 *
 * Payer proof TLV types:
 *   241  - proof_signature    (BIP-340 signature by invreq_payer_id)
 *   1001 - proof_preimage     (32-byte payment preimage)
 *   1002 - proof_omitted_tlvs (array of BigSize marker numbers)
 *   1003 - proof_missing_hashes (array of sha256 hashes for merkle reconstruction)
 *   1004 - proof_leaf_hashes  (array of sha256 nonce hashes for included TLVs)
 *   1005 - proof_note         (optional UTF-8 note)
 */

import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';
import type { TlvRecord } from './tlv.js';
import { parseTlvStream, serializeTlvRecord } from './tlv.js';
import { readBigSize, writeBigSize } from './bigsize.js';
import {
  taggedHash,
  tlvToBytes,
  branchHash,
  computePerTlvBranches,
  computeMerkleRoot,
} from './merkle.js';
import { encodeBolt12 } from './bech32.js';
import { isSignatureType, toHex } from './utils.js';

const encoder = new TextEncoder();

// Payer proof specific TLV types
export const PP_PROOF_SIGNATURE = 241n;
export const PP_PREIMAGE = 1001n;
export const PP_OMITTED_TLVS = 1002n;
export const PP_MISSING_HASHES = 1003n;
export const PP_LEAF_HASHES = 1004n;
export const PP_NOTE = 1005n;

// Invoice field types needed for validation
const INVREQ_METADATA = 0n;
const INVREQ_PAYER_ID = 88n;
const INVOICE_PAYMENT_HASH = 168n;
const INVOICE_NODE_ID = 176n;
const SIGNATURE = 240n;
const LOW_MARKER_MAX = 239n;
const HIGH_MARKER_MIN = 1_000_000_000n;
const HIGH_MARKER_MAX = 3_999_999_999n;
// Payer-proof data range (PAYER_PROOF_DATA_TYPES): 1001..=999_999_999. The only
// defined types here are the known proof fields 1001..=1005.
const PP_DATA_RANGE_MIN = 1001n;

// Required TLV types that must always be included in a payer proof
const REQUIRED_TYPES = new Set([INVREQ_PAYER_ID, INVOICE_PAYMENT_HASH, INVOICE_NODE_ID]);

/**
 * Tagged hash using a pre-computed tag hash.
 */
function taggedHashWithPrecomputedTag(tagHash: Uint8Array, msg: Uint8Array): Uint8Array {
  return sha256(concatBytes(tagHash, tagHash, msg));
}

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
 * Compute the leaf+nonce branch for a TLV record given its nonce hash.
 */
function leafBranch(tlvBytes: Uint8Array, nonceHash: Uint8Array): Uint8Array {
  const leafTag = encoder.encode('LnLeaf');
  const leaf = taggedHash(leafTag, tlvBytes);
  return branchHash(leaf, nonceHash);
}

export interface PayerProofFields {
  /** Original payer proof TLV records */
  records: TlvRecord[];
  /** Included TLV records (non-signature, non-payer-proof-specific) */
  includedRecords: TlvRecord[];
  /** The invoice signature (type 240) */
  signature: Uint8Array;
  /** Payer proof signature (type 241) */
  proofSignature: Uint8Array;
  /** Deprecated alias for proofSignature. */
  payerSignature: Uint8Array;
  /** Payment preimage (type 1001, 32 bytes) */
  preimage: Uint8Array;
  /** Marker numbers for omitted TLVs (type 1002) */
  omittedTlvs: bigint[];
  /** Missing merkle branch hashes (type 1003) */
  missingHashes: Uint8Array[];
  /** Nonce hashes for included non-signature TLVs (type 1004) */
  leafHashes: Uint8Array[];
  /** Optional proof note (type 1005) */
  proofNote: string;
  /** Deprecated alias for proofNote. */
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
  let proofSignature: Uint8Array | null = null;
  let preimage: Uint8Array | null = null;
  let omittedTlvsRaw: Uint8Array | null = null;
  let missingHashesRaw: Uint8Array | null = null;
  let leafHashesRaw: Uint8Array | null = null;
  let proofNoteRaw: Uint8Array | null = null;
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
    } else if (type === PP_PROOF_SIGNATURE) {
      if (record.value.length !== 64) {
        throw new Error('Invalid proof_signature: expected 64 bytes');
      }
      proofSignature = record.value;
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
    } else if (type === PP_NOTE) {
      proofNoteRaw = record.value;
    } else if (type >= PP_DATA_RANGE_MIN && type < HIGH_MARKER_MIN) {
      // Unknown TLV in the payer-proof data range (the known proof fields
      // 1001..=1005 are matched above). Per the BOLT "it's ok to be odd" rule,
      // an unknown even type is mandatory and MUST be rejected; an unknown odd
      // type is ignorable. Either way it is not an invoice field, so it is not
      // reconstructed as an invoice leaf (it stays committed by proof_signature).
      if (type % 2n === 0n) {
        throw new Error(`Payer proof contains unknown even TLV type ${type} in the proof data range`);
      }
    } else if (isIncludedInvoiceType(type)) {
      // Genuine invoice field. Types in the signature range (240..=1000) and
      // the payer-proof data range (1001..=999_999_999) are proof-container
      // types, not invoice leaves, so they are excluded here (matching the
      // reference implementation). Unknown ignorable (odd) TLVs in the data
      // range are tolerated rather than mis-counted as invoice fields.
      includedRecords.push(record);
    }
  }

  // Required fields check
  if (!payerId) {
    throw new Error('Missing invreq_payer_id');
  }
  if (!invoicePaymentHash) {
    throw new Error('Missing invoice_payment_hash');
  }
  if (!invoiceNodeId) {
    throw new Error('Missing invoice_node_id');
  }
  if (!signature) {
    throw new Error('Missing signature');
  }
  if (!proofSignature) {
    throw new Error('Missing proof_signature');
  }
  if (!preimage) {
    throw new Error('Missing proof_preimage');
  }
  if (!missingHashesRaw) {
    throw new Error('Missing proof_missing_hashes');
  }
  if (!leafHashesRaw) {
    throw new Error('Missing proof_leaf_hashes');
  }

  // Parse omitted_tlvs
  const omittedTlvs = omittedTlvsRaw ? parseBigSizeArray(omittedTlvsRaw) : [];

  // Validate omitted_tlvs
  validateOmittedTlvs(omittedTlvs, includedRecords);

  // Parse missing_hashes
  const missingHashes = parseSha256Array(missingHashesRaw);

  // Parse leaf_hashes
  const leafHashes = parseSha256Array(leafHashesRaw);

  // Validate leaf_hashes count matches included non-signature TLVs
  if (leafHashes.length !== includedRecords.length) {
    throw new Error(
      `leaf_hashes count (${leafHashes.length}) must match included non-signature TLV count (${includedRecords.length})`
    );
  }

  // Validate preimage matches payment hash
  const computedHash = sha256(preimage);
  if (toHex(computedHash) !== toHex(invoicePaymentHash)) {
    throw new Error('SHA256(preimage) does not match invoice_payment_hash');
  }

  // Extract optional proof note
  let proofNote = '';
  if (proofNoteRaw && proofNoteRaw.length > 0) {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
      proofNote = decoder.decode(proofNoteRaw);
    } catch {
      throw new Error('Invalid UTF-8 in proof_note');
    }
  }

  return {
    records,
    includedRecords,
    signature,
    proofSignature,
    payerSignature: proofSignature,
    preimage,
    omittedTlvs,
    missingHashes,
    leafHashes,
    proofNote,
    payerNote: proofNote,
    invoicePaymentHash,
    invoiceNodeId,
    payerId,
  };
}

/**
 * Validate the omitted_tlvs array.
 */
function validateOmittedTlvs(omittedTlvs: bigint[], includedRecords: TlvRecord[]): void {
  const includedTypes = new Set(includedRecords.map(r => r.type));
  const sortedIncludedTypes = includedRecords.map(r => r.type);

  // Must be in strict ascending order (no duplicates)
  for (let i = 1; i < omittedTlvs.length; i++) {
    if (omittedTlvs[i] <= omittedTlvs[i - 1]) {
      throw new Error('omitted_tlvs must be in strict ascending order');
    }
  }

  let expectedNext = nextMarker(0n);
  let includedIndex = 0;

  for (const marker of omittedTlvs) {
    if (marker === 0n) {
      throw new Error('omitted_tlvs must not contain 0');
    }
    if (!isAllowedOmittedMarker(marker)) {
      throw new Error(`omitted_tlvs marker ${marker} is outside allowed ranges`);
    }
    if (includedTypes.has(marker)) {
      throw new Error(`omitted_tlvs must not contain included TLV type ${marker}`);
    }

    if (marker !== expectedNext) {
      let justifiedByIncludedType = false;
      while (includedIndex < sortedIncludedTypes.length) {
        const includedType = sortedIncludedTypes[includedIndex++];
        if (nextMarker(includedType) === marker) {
          justifiedByIncludedType = true;
          break;
        }
        if (includedType >= marker) {
          throw new Error(`omitted_tlvs marker ${marker} is not minimally sequential`);
        }
      }
      if (!justifiedByIncludedType) {
        throw new Error(`omitted_tlvs marker ${marker} is not minimally sequential`);
      }
    }

    expectedNext = nextMarker(marker);
  }
}

function isAllowedOmittedMarker(marker: bigint): boolean {
  return (marker >= 1n && marker <= LOW_MARKER_MAX) ||
    (marker >= HIGH_MARKER_MIN && marker <= HIGH_MARKER_MAX);
}

/**
 * Whether a TLV type is a genuine invoice field (and thus an invoice merkle
 * leaf), as opposed to a proof-container type.
 *
 * Invoice fields live in the normal range (< 240) or the experimental range
 * (>= 1_000_000_000). The signature range (240..=1000) and the payer-proof
 * data range (1001..=999_999_999) are proof-container types and MUST NOT be
 * reconstructed as invoice leaves. Mirrors rust-lightning's `tlv_stream_iter`,
 * which strips both SIGNATURE_TYPES and PAYER_PROOF_DATA_TYPES.
 */
function isIncludedInvoiceType(type: bigint): boolean {
  return type < SIGNATURE || type >= HIGH_MARKER_MIN;
}

function nextMarker(value: bigint): bigint {
  return value === LOW_MARKER_MAX ? HIGH_MARKER_MIN : value + 1n;
}

/**
 * Largest power of 2 less than n. Used for recursive tree splitting.
 */
function largestPow2LessThan(n: number): number {
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

interface MerkleNode {
  hash: Uint8Array;
  isKnown: boolean;
}

/**
 * Check if all nodes in a slice are unknown.
 */
function allUnknown(nodes: MerkleNode[]): boolean {
  return nodes.every(n => !n.isKnown);
}

/**
 * Recursively build merkle tree in post-order, pulling missing hashes.
 *
 * Before recursing into a child, checks if it's entirely unknown. If so,
 * pulls its subtree hash from missing_hashes without recursing. This ensures
 * hashes are consumed in the same order they were produced.
 */
function rebuildTreeRecursive(
  nodes: MerkleNode[],
  missingHashes: Uint8Array[],
  missingIdx: { value: number },
): MerkleNode {
  if (nodes.length === 1) {
    return nodes[0];
  }

  const split = largestPow2LessThan(nodes.length);
  const leftNodes = nodes.slice(0, split);
  const rightNodes = nodes.slice(split);
  const leftAllUnknown = allUnknown(leftNodes);
  const rightAllUnknown = allUnknown(rightNodes);

  if (leftAllUnknown && rightAllUnknown) {
    return { hash: new Uint8Array(0), isKnown: false };
  }

  if (leftAllUnknown) {
    const right = rebuildTreeRecursive(rightNodes, missingHashes, missingIdx);
    if (missingIdx.value >= missingHashes.length) {
      throw new Error('Not enough missing_hashes to reconstruct merkle tree');
    }
    const leftHash = missingHashes[missingIdx.value++];
    return { hash: branchHash(leftHash, right.hash), isKnown: true };
  }

  if (rightAllUnknown) {
    const left = rebuildTreeRecursive(leftNodes, missingHashes, missingIdx);
    if (missingIdx.value >= missingHashes.length) {
      throw new Error('Not enough missing_hashes to reconstruct merkle tree');
    }
    const rightHash = missingHashes[missingIdx.value++];
    return { hash: branchHash(left.hash, rightHash), isKnown: true };
  }

  const left = rebuildTreeRecursive(leftNodes, missingHashes, missingIdx);
  const right = rebuildTreeRecursive(rightNodes, missingHashes, missingIdx);
  return { hash: branchHash(left.hash, right.hash), isKnown: true };
}

/**
 * Reconstruct the Merkle root from a payer proof.
 *
 * The tree has N positions: 1 implicit (type 0) + omitted markers + included records.
 * Uses recursive DFS tree building to consume missing_hashes in the correct order.
 */
export function reconstructMerkleRoot(proof: PayerProofFields): Uint8Array {
  // Build ordered list: implicit type 0 + interleaved included/omitted positions.
  const allNodes: MerkleNode[] = [];
  const positions = reconstructPositions(proof.includedRecords, proof.omittedTlvs);
  let includedHashIndex = 0;

  for (const isIncluded of positions) {
    if (isIncluded) {
      const record = proof.includedRecords[includedHashIndex];
      const nonceHash = proof.leafHashes[includedHashIndex];
      const hash = leafBranch(tlvToBytes(record), nonceHash);
      allNodes.push({ hash, isKnown: true });
      includedHashIndex++;
    } else {
      allNodes.push({ hash: new Uint8Array(0), isKnown: false });
    }
  }

  const missingIdx = { value: 0 };
  const root = rebuildTreeRecursive(allNodes, proof.missingHashes, missingIdx);

  if (missingIdx.value !== proof.missingHashes.length) {
    throw new Error(
      `Excess missing_hashes: used ${missingIdx.value} of ${proof.missingHashes.length}`
    );
  }

  if (!root.isKnown) {
    throw new Error('Failed to reconstruct merkle root');
  }

  return root.hash;
}

function reconstructPositions(includedRecords: TlvRecord[], omittedMarkers: bigint[]): boolean[] {
  const positions: boolean[] = [false]; // TLV 0 is always omitted.
  let includedIndex = 0;
  let markerIndex = 0;
  let previousMarker = 0n;

  while (includedIndex < includedRecords.length || markerIndex < omittedMarkers.length) {
    if (markerIndex >= omittedMarkers.length) {
      positions.push(true);
      includedIndex++;
    } else if (includedIndex >= includedRecords.length) {
      positions.push(false);
      previousMarker = omittedMarkers[markerIndex++];
    } else {
      const marker = omittedMarkers[markerIndex];
      const includedType = includedRecords[includedIndex].type;

      if (marker === nextMarker(previousMarker)) {
        positions.push(false);
        previousMarker = marker;
        markerIndex++;
      } else {
        positions.push(true);
        previousMarker = includedType;
        includedIndex++;
      }
    }
  }

  return positions;
}

/**
 * Verify a payer proof's signatures.
 */
export function verifyPayerProof(proof: PayerProofFields): {
  valid: boolean;
  merkleRoot: Uint8Array;
  proofMerkleRoot?: Uint8Array;
  error?: string;
} {
  try {
    const merkleRoot = reconstructMerkleRoot(proof);

    // Verify invoice signature: tag = "lightninginvoicesignature"
    const invoiceSigTag = encoder.encode('lightninginvoicesignature');
    const invoiceSigMsg = taggedHash(invoiceSigTag, merkleRoot);
    const nodeIdX = proof.invoiceNodeId.length === 33
      ? proof.invoiceNodeId.slice(1)
      : proof.invoiceNodeId;

    const invoiceSigValid = schnorr.verify(proof.signature, invoiceSigMsg, nodeIdX);
    if (!invoiceSigValid) {
      return { valid: false, merkleRoot, error: 'Invalid invoice signature' };
    }

    // Verify proof_signature over the payer_proof TLV stream.
    const proofMerkleRoot = computeMerkleRoot(proof.records);
    const payerSigTag = encoder.encode('lightningpayer_proofproof_signature');
    const payerMsg = taggedHash(payerSigTag, proofMerkleRoot);
    const payerIdX = proof.payerId.length === 33
      ? proof.payerId.slice(1)
      : proof.payerId;

    const payerSigValid = schnorr.verify(proof.proofSignature, payerMsg, payerIdX);
    if (!payerSigValid) {
      return { valid: false, merkleRoot, proofMerkleRoot, error: 'Invalid proof signature' };
    }

    return { valid: true, merkleRoot, proofMerkleRoot };
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e);
    return { valid: false, merkleRoot: new Uint8Array(32), error: message };
  }
}

// ---- Creation ----

export interface CreatePayerProofParams {
  /** Hex-encoded invoice TLV stream */
  invoiceHex: string;
  /** Hex-encoded 32-byte payment preimage */
  preimageHex: string;
  /** Hex-encoded 32-byte payer secret key (for BIP-340 signing) */
  payerSecretKeyHex: string;
  /** Additional TLV types to include beyond the required ones */
  includedTlvTypes?: number[];
  /** Optional payer note (UTF-8) */
  note?: string;
}

export interface CreatePayerProofResult {
  /** Hex-encoded proof TLV stream */
  proofHex: string;
  /** Bech32-encoded proof with "lnp" prefix */
  proofBech32: string;
  /** 32-byte invoice merkle root */
  merkleRoot: Uint8Array;
  /** 32-byte payer_proof merkle root */
  proofMerkleRoot: Uint8Array;
}

/**
 * Compute omitted TLV markers for the payer proof.
 *
 * Markers assign minimal values to omitted positions:
 * - Type 0 is always implicit (no marker)
 * - Before first included type: markers start at 1 and increment
 * - After an included type: markers start at included_type+1 and increment
 */
function computeOmittedMarkers(
  nonSigTypes: bigint[],
  includedTypes: Set<bigint>,
): bigint[] {
  const markers: bigint[] = [];
  let marker = nextMarker(0n);

  for (const type of nonSigTypes) {
    if (type === 0n) {
      continue; // implicit
    }

    if (includedTypes.has(type)) {
      marker = nextMarker(type);
    } else {
      markers.push(marker);
      marker = nextMarker(marker);
    }
  }

  return markers;
}

/**
 * Compute subtree hash for a fully-unknown subtree (creator side).
 */
function computeSubtreeHash(nodes: MerkleNode[]): Uint8Array {
  if (nodes.length === 1) {
    return nodes[0].hash;
  }
  const split = largestPow2LessThan(nodes.length);
  const left = computeSubtreeHash(nodes.slice(0, split));
  const right = computeSubtreeHash(nodes.slice(split));
  return branchHash(left, right);
}

/**
 * Recursively compute missing hashes in post-order depth-first order.
 */
function collectMissingRecursive(
  nodes: MerkleNode[],
  missing: Uint8Array[],
): MerkleNode {
  if (nodes.length === 1) {
    return nodes[0];
  }

  const split = largestPow2LessThan(nodes.length);
  const leftNodes = nodes.slice(0, split);
  const rightNodes = nodes.slice(split);
  const leftAllUnknown = allUnknown(leftNodes);
  const rightAllUnknown = allUnknown(rightNodes);

  if (leftAllUnknown && rightAllUnknown) {
    const hash = branchHash(computeSubtreeHash(leftNodes), computeSubtreeHash(rightNodes));
    return { hash, isKnown: false };
  }

  if (leftAllUnknown) {
    const leftHash = computeSubtreeHash(leftNodes);
    const right = collectMissingRecursive(rightNodes, missing);
    missing.push(leftHash);
    return { hash: branchHash(leftHash, right.hash), isKnown: true };
  }

  if (rightAllUnknown) {
    const left = collectMissingRecursive(leftNodes, missing);
    const rightHash = computeSubtreeHash(rightNodes);
    missing.push(rightHash);
    return { hash: branchHash(left.hash, rightHash), isKnown: true };
  }

  const left = collectMissingRecursive(leftNodes, missing);
  const right = collectMissingRecursive(rightNodes, missing);
  return { hash: branchHash(left.hash, right.hash), isKnown: true };
}

/**
 * Compute the missing hashes needed for merkle tree reconstruction.
 * Uses recursive DFS to produce hashes in the same order the verifier consumes them.
 */
function computeMissingHashesForProof(
  allBranches: Uint8Array[],
  isIncluded: boolean[],
): Uint8Array[] {
  const nodes: MerkleNode[] = allBranches.map((hash, i) => ({
    hash,
    isKnown: isIncluded[i],
  }));

  const missing: Uint8Array[] = [];
  collectMissingRecursive(nodes, missing);
  return missing;
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function makeTlv(type: bigint, value: Uint8Array): TlvRecord {
  return { type, length: BigInt(value.length), value };
}

/**
 * Create a BOLT12 payer proof from an invoice, preimage, and payer secret key.
 */
export function createPayerProof(params: CreatePayerProofParams): CreatePayerProofResult {
  const invoiceBytes = fromHex(params.invoiceHex);
  const preimage = fromHex(params.preimageHex);
  const payerSecretKey = fromHex(params.payerSecretKeyHex);

  // Parse invoice TLV records
  const invoiceRecords = parseTlvStream(invoiceBytes);

  // Find required fields
  const nonSigRecords = invoiceRecords.filter(r => !isSignatureType(r.type));
  const sigRecord = invoiceRecords.find(r => r.type === SIGNATURE);
  if (!sigRecord) {
    throw new Error('Invoice missing signature (type 240)');
  }

  const paymentHashRecord = nonSigRecords.find(r => r.type === INVOICE_PAYMENT_HASH);
  if (!paymentHashRecord) {
    throw new Error('Invoice missing payment_hash (type 168)');
  }

  // Verify preimage
  const computedHash = sha256(preimage);
  const paymentHash = paymentHashRecord.value;
  if (computedHash.length !== paymentHash.length ||
      !computedHash.every((b, i) => b === paymentHash[i])) {
    throw new Error('SHA256(preimage) does not match invoice_payment_hash');
  }

  // Compute merkle root from invoice
  const merkleRoot = computeMerkleRoot(invoiceRecords);

  // Determine included types
  const INVOICE_FEATURES = 174n;
  const additionalTypes = new Set((params.includedTlvTypes || []).map(BigInt));
  const hasInvoiceFeatures = nonSigRecords.some(r => r.type === INVOICE_FEATURES);
  const includedTypes = new Set([
    ...REQUIRED_TYPES,
    ...additionalTypes,
    ...(hasInvoiceFeatures ? [INVOICE_FEATURES] : []),
  ]);

  // Filter: only types actually present in the invoice and not type 0
  const nonSigTypes = nonSigRecords.map(r => r.type);

  // Compute per-TLV branches
  const { branches, nonceTagHash } = computePerTlvBranches(invoiceRecords);

  // Build isIncluded array (type 0 is always NOT included)
  const isIncluded = nonSigRecords.map(r => r.type !== 0n && includedTypes.has(r.type));

  // Compute omitted markers
  const omittedMarkers = computeOmittedMarkers(nonSigTypes, includedTypes);

  // Compute nonce hashes (leaf_hashes) for included TLVs
  const includedNonceHashes: Uint8Array[] = [];
  for (let i = 0; i < nonSigRecords.length; i++) {
    if (isIncluded[i]) {
      const typeBytes = writeBigSize(nonSigRecords[i].type);
      const nonce = taggedHashWithPrecomputedTag(nonceTagHash, typeBytes);
      includedNonceHashes.push(nonce);
    }
  }

  // Compute missing hashes
  const missingHashes = computeMissingHashesForProof(branches, isIncluded);

  const noteBytes = params.note ? encoder.encode(params.note) : new Uint8Array(0);

  // Build proof TLV records, excluding proof_signature until its merkle root is known.
  const proofRecordsWithoutProofSignature: TlvRecord[] = [];

  // Add included invoice records (non-sig, non-type-0)
  for (const record of nonSigRecords) {
    if (record.type !== 0n && includedTypes.has(record.type)) {
      proofRecordsWithoutProofSignature.push(record);
    }
  }

  // Type 240: invoice signature
  proofRecordsWithoutProofSignature.push(makeTlv(SIGNATURE, sigRecord.value));

  // Type 1001: preimage
  proofRecordsWithoutProofSignature.push(makeTlv(PP_PREIMAGE, preimage));

  // Type 1002: omitted_tlvs
  if (omittedMarkers.length > 0) {
    const omittedValue = concatBytes(...omittedMarkers.map(m => writeBigSize(m)));
    proofRecordsWithoutProofSignature.push(makeTlv(PP_OMITTED_TLVS, omittedValue));
  }

  // Type 1003: missing_hashes
  const missingValue = missingHashes.length > 0 ? concatBytes(...missingHashes) : new Uint8Array(0);
  proofRecordsWithoutProofSignature.push(makeTlv(PP_MISSING_HASHES, missingValue));

  // Type 1004: leaf_hashes
  const leafHashesValue = includedNonceHashes.length > 0
    ? concatBytes(...includedNonceHashes)
    : new Uint8Array(0);
  proofRecordsWithoutProofSignature.push(makeTlv(PP_LEAF_HASHES, leafHashesValue));

  // Type 1005: proof_note
  if (noteBytes.length > 0) {
    proofRecordsWithoutProofSignature.push(makeTlv(PP_NOTE, noteBytes));
  }

  proofRecordsWithoutProofSignature.sort((a, b) => Number(a.type - b.type));

  // Sign the payer_proof merkle root using proof_signature.
  const proofMerkleRoot = computeMerkleRoot(proofRecordsWithoutProofSignature);
  const payerSigTag = encoder.encode('lightningpayer_proofproof_signature');
  const payerMsg = taggedHash(payerSigTag, proofMerkleRoot);
  const proofSig = schnorr.sign(payerMsg, payerSecretKey);

  const proofRecords = [
    ...proofRecordsWithoutProofSignature,
    makeTlv(PP_PROOF_SIGNATURE, proofSig),
  ];
  proofRecords.sort((a, b) => Number(a.type - b.type));

  // Serialize to bytes
  const proofBytes = concatBytes(...proofRecords.map(serializeTlvRecord));
  const proofHex = toHex(proofBytes);
  const proofBech32 = encodeBolt12('lnp', proofBytes);

  return { proofHex, proofBech32, merkleRoot, proofMerkleRoot };
}
