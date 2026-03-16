/**
 * Merkle tree computation for BOLT12 signature verification.
 *
 * Each TLV record is paired with a nonce derived from all TLVs:
 *   leaf    = H("LnLeaf", tlv_bytes)
 *   nonce   = H("LnAll" || all_tlvs, individual_tlv_bytes)
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
 * Serialize a single TLV record to its wire format (type + length + value).
 */
function tlvToBytes(record: TlvRecord): Uint8Array {
  const typeBytes = writeBigSize(record.type);
  const lengthBytes = writeBigSize(record.length);
  return concatBytes(typeBytes, lengthBytes, record.value);
}

/**
 * Compute a branch from a pair of nodes, ordering them lexicographically.
 */
function branchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  const tag = encoder.encode('LnBranch');
  const [smaller, larger] = compareBytes(a, b) < 0 ? [a, b] : [b, a];
  return taggedHash(tag, concatBytes(smaller, larger));
}

/**
 * Compute the merkle root from an array of TLV records.
 *
 * For signature verification, exclude the signature TLV (type 240).
 * For offer_id computation, only include offer TLVs (types 1-79 and
 * 1000000000-1999999999).
 */
export function computeMerkleRoot(records: TlvRecord[]): Uint8Array {
  if (records.length === 0) {
    throw new Error('Cannot compute merkle root of empty TLV set');
  }

  // Concatenate all TLV bytes for nonce computation
  const allTlvBytes = concatBytes(...records.map(tlvToBytes));

  // Compute leaf+nonce branch for each TLV
  const leafTag = encoder.encode('LnLeaf');
  const nonceTag = concatBytes(encoder.encode('LnAll'), allTlvBytes);

  let nodes: Uint8Array[] = records.map((record) => {
    const tlvBytes = tlvToBytes(record);
    const leaf = taggedHash(leafTag, tlvBytes);
    const nonce = taggedHash(nonceTag, tlvBytes);
    return branchHash(leaf, nonce);
  });

  // Build the tree bottom-up
  while (nodes.length > 1) {
    const parents: Uint8Array[] = [];
    let i = 0;
    while (i < nodes.length) {
      if (i + 1 < nodes.length) {
        parents.push(branchHash(nodes[i], nodes[i + 1]));
        i += 2;
      } else {
        // Odd node promoted
        parents.push(nodes[i]);
        i += 1;
      }
    }
    nodes = parents;
  }

  return nodes[0];
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
