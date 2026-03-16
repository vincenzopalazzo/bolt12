/**
 * Merkle tree computation for BOLT12 signature verification.
 *
 * Each TLV record is paired with a nonce derived from the first TLV:
 *   leaf    = H("LnLeaf", tlv_bytes)
 *   nonce   = H(SHA256("LnNonce" || first_tlv_bytes), type_bytes)
 *   branch  = H("LnBranch", sorted(leaf, nonce))
 *
 * These branches are then paired up in a binary tree:
 *   parent  = H("LnBranch", sorted(left, right))
 *
 * The root of the tree is the merkle root (offer_id for offers).
 *
 * Signature verification uses:
 *   msg = H("lightning" || messagename || "signature", merkle_root)
 */

import { sha256 } from '@noble/hashes/sha2';
import { concatBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';
import type { TlvRecord } from './tlv.js';
import { writeBigSize } from './bigsize.js';
import { compareBytes } from './utils.js';

const encoder = new TextEncoder();

/**
 * Tagged hash: H(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 */
export function taggedHash(tag: Uint8Array, msg: Uint8Array): Uint8Array {
  const tagHash = sha256(tag);
  return sha256(concatBytes(tagHash, tagHash, msg));
}

/**
 * Tagged hash using a pre-computed tag hash.
 */
function taggedHashWithHash(tagHash: Uint8Array, msg: Uint8Array): Uint8Array {
  return sha256(concatBytes(tagHash, tagHash, msg));
}

/**
 * Serialize a single TLV record to its wire format (type + length + value).
 */
export function tlvToBytes(record: TlvRecord): Uint8Array {
  const typeBytes = writeBigSize(record.type);
  const lengthBytes = writeBigSize(record.length);
  return concatBytes(typeBytes, lengthBytes, record.value);
}

/**
 * Compute a branch from a pair of nodes, ordering them lexicographically.
 */
export function branchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  const branchTagHash = sha256(encoder.encode('LnBranch'));
  const [smaller, larger] = compareBytes(a, b) < 0 ? [a, b] : [b, a];
  return taggedHashWithHash(branchTagHash, concatBytes(smaller, larger));
}

/** Signature TLV type range (240-1000 inclusive). */
function isSignatureType(type: bigint): boolean {
  return type >= 240n && type <= 1000n;
}

/**
 * Compute per-TLV branch hashes (leaf+nonce combined).
 * Returns the branch hash for each non-signature TLV, and the nonce tag hash.
 */
export function computePerTlvBranches(records: TlvRecord[]): {
  branches: Uint8Array[];
  nonceTagHash: Uint8Array;
  leafTagHash: Uint8Array;
  branchTagHash: Uint8Array;
} {
  const nonSig = records.filter(r => !isSignatureType(r.type));
  if (nonSig.length === 0) {
    throw new Error('Cannot compute merkle root of empty TLV set');
  }

  // Nonce tag: SHA256("LnNonce" || first_record_bytes)
  const firstRecBytes = tlvToBytes(nonSig[0]);
  const nonceTagHash = sha256(concatBytes(encoder.encode('LnNonce'), firstRecBytes));

  const leafTagHash = sha256(encoder.encode('LnLeaf'));
  const branchTagHash = sha256(encoder.encode('LnBranch'));

  const branches: Uint8Array[] = nonSig.map((record) => {
    const recBytes = tlvToBytes(record);
    const typeBytes = writeBigSize(record.type);

    const leaf = taggedHashWithHash(leafTagHash, recBytes);
    const nonce = taggedHashWithHash(nonceTagHash, typeBytes);

    // Combine leaf and nonce with lexicographic ordering
    const [smaller, larger] = compareBytes(leaf, nonce) < 0 ? [leaf, nonce] : [nonce, leaf];
    return taggedHashWithHash(branchTagHash, concatBytes(smaller, larger));
  });

  return { branches, nonceTagHash, leafTagHash, branchTagHash };
}

/**
 * Build merkle tree from per-TLV branch hashes, bottom-up.
 */
function buildMerkleTree(nodes: Uint8Array[]): Uint8Array {
  const branchTagHash = sha256(encoder.encode('LnBranch'));

  while (nodes.length > 1) {
    const parents: Uint8Array[] = [];
    let i = 0;
    while (i < nodes.length) {
      if (i + 1 < nodes.length) {
        const [smaller, larger] = compareBytes(nodes[i], nodes[i + 1]) < 0
          ? [nodes[i], nodes[i + 1]]
          : [nodes[i + 1], nodes[i]];
        parents.push(taggedHashWithHash(branchTagHash, concatBytes(smaller, larger)));
        i += 2;
      } else {
        parents.push(nodes[i]);
        i += 1;
      }
    }
    nodes = parents;
  }

  return nodes[0];
}

/**
 * Compute the merkle root from an array of TLV records.
 *
 * Excludes signature TLVs (types 240-1000) from the tree.
 */
export function computeMerkleRoot(records: TlvRecord[]): Uint8Array {
  const { branches } = computePerTlvBranches(records);
  return buildMerkleTree([...branches]);
}

/**
 * Compute the signature verification message.
 * tag = "lightning" + messagename + "signature"
 */
export function signatureTag(messageName: string): Uint8Array {
  return encoder.encode(`lightning${messageName}signature`);
}

/**
 * Verify a BIP340 Schnorr signature on a BOLT12 message.
 */
export function verifySignature(
  messageName: string,
  merkleRoot: Uint8Array,
  pubkey32: Uint8Array,
  signature: Uint8Array,
): boolean {
  const tag = signatureTag(messageName);
  const msg = taggedHash(tag, merkleRoot);
  try {
    return schnorr.verify(signature, msg, pubkey32);
  } catch {
    return false;
  }
}
