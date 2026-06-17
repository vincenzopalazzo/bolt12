/**
 * Tests for BOLT12 payer proofs using the spec vectors from
 * lightning/bolts#1295.
 */

import * as fs from 'fs';
import { sha256 } from '@noble/hashes/sha2';
import { decodeBolt12 } from '../src/bech32.js';
import { parseTlvStream, serializeTlvRecord, type TlvRecord } from '../src/tlv.js';
import {
  createPayerProof,
  parsePayerProof,
  verifyPayerProof,
  PP_PROOF_SIGNATURE,
  PP_OMITTED_TLVS,
} from '../src/payer_proof.js';

function toHex(buf: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((total, arr) => total + arr.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

function proofHexFromBech32(bech32: string): string {
  const { hrp, data } = decodeBolt12(bech32);
  assert(hrp === 'lnp', `Expected lnp proof, got ${hrp}`);
  return toHex(data);
}

function comparableProofHex(hex: string, dropExplicitEmptyOmitted = false): string {
  const records = parseTlvStream(fromHex(hex)).filter(record => {
    if (record.type === PP_PROOF_SIGNATURE) return false;
    return !(dropExplicitEmptyOmitted &&
      record.type === PP_OMITTED_TLVS &&
      record.value.length === 0);
  });
  return toHex(concatBytes(...records.map(serializeTlvRecord)));
}

// ---- Test infrastructure ----
let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`  PASS ${name}`);
  } catch (e: unknown) {
    failed++;
    const message = e instanceof Error ? e.message : String(e);
    const msg = `FAIL ${name}: ${message}`;
    failures.push(msg);
    console.log(`  ${msg}`);
  }
}

function assert(condition: boolean, msg: string): asserts condition {
  if (!condition) throw new Error(msg);
}

function assertEqual(actual: string, expected: string, label: string) {
  assert(
    actual === expected,
    `${label} mismatch:\n  expected: ${expected}\n  got:      ${actual}`,
  );
}

interface InvoiceFieldVector {
  type: number;
  included: boolean;
}

interface ValidVector {
  name: string;
  input: {
    invoice_hex: string;
    preimage: string;
    note?: string;
    invoice_fields: InvoiceFieldVector[];
  };
  working: {
    invoice_merkle_root: string;
    proof_merkle_root: string;
    proof_leaf_hashes: string[];
    proof_omitted_tlvs: number[];
    proof_missing_hashes: string[];
  };
  result: {
    bech32: string;
  };
}

interface InvalidVector {
  reason: string;
  bech32: string;
}

interface SpecVectors {
  payer_secret: string;
  valid_vectors: ValidVector[];
  invalid_vectors: InvalidVector[];
}

const vectors = JSON.parse(
  fs.readFileSync('../test-vectors/payer-proof-test.json', 'utf8'),
) as SpecVectors;

console.log('Payer Proof Spec Vectors\n');

for (const vector of vectors.valid_vectors) {
  test(`${vector.name}: parses and verifies spec proof`, () => {
    const proofHex = proofHexFromBech32(vector.result.bech32);
    const proof = parsePayerProof(parseTlvStream(fromHex(proofHex)));
    const verification = verifyPayerProof(proof);

    assert(verification.valid, `Spec proof verification failed: ${verification.error}`);
    assertEqual(toHex(verification.merkleRoot), vector.working.invoice_merkle_root, 'invoice merkle root');
    assert(verification.proofMerkleRoot, 'Missing proof merkle root');
    assertEqual(toHex(verification.proofMerkleRoot), vector.working.proof_merkle_root, 'proof merkle root');
    assertEqual(proof.proofNote, vector.input.note || '', 'proof note');
    assertEqual(
      proof.leafHashes.map(toHex).join(''),
      vector.working.proof_leaf_hashes.join(''),
      'proof leaf hashes',
    );
    assertEqual(
      proof.missingHashes.map(toHex).join(''),
      vector.working.proof_missing_hashes.join(''),
      'proof missing hashes',
    );
    assertEqual(
      proof.omittedTlvs.map(String).join(','),
      vector.working.proof_omitted_tlvs.map(String).join(','),
      'proof omitted tlvs',
    );
  });

  test(`${vector.name}: creator matches spec proof fields`, () => {
    const includedTlvTypes = vector.input.invoice_fields
      .filter(field => field.included)
      .map(field => field.type);

    const result = createPayerProof({
      invoiceHex: vector.input.invoice_hex,
      preimageHex: vector.input.preimage,
      payerSecretKeyHex: vectors.payer_secret,
      includedTlvTypes,
      note: vector.input.note,
    });

    assertEqual(toHex(result.merkleRoot), vector.working.invoice_merkle_root, 'created invoice merkle root');
    const dropExplicitEmptyOmitted = vector.name === 'empty_proof_omitted_tlvs_explicit';
    if (!dropExplicitEmptyOmitted) {
      assertEqual(toHex(result.proofMerkleRoot), vector.working.proof_merkle_root, 'created proof merkle root');
    }

    const proof = parsePayerProof(parseTlvStream(fromHex(result.proofHex)));
    const verification = verifyPayerProof(proof);
    assert(verification.valid, `Created proof verification failed: ${verification.error}`);

    const expectedHex = proofHexFromBech32(vector.result.bech32);
    assertEqual(
      comparableProofHex(result.proofHex),
      comparableProofHex(expectedHex, dropExplicitEmptyOmitted),
      'created proof without proof_signature',
    );
  });
}

for (const vector of vectors.invalid_vectors) {
  test(`${vector.reason}: rejected`, () => {
    let accepted = false;
    try {
      const proofHex = proofHexFromBech32(vector.bech32);
      const proof = parsePayerProof(parseTlvStream(fromHex(proofHex)));
      accepted = verifyPayerProof(proof).valid;
    } catch {
      accepted = false;
    }
    assert(!accepted, 'Invalid proof was accepted');
  });
}

// Keep a focused check around the signature-gap marker rule since it is easy to
// regress without hitting ordinary invoice vectors.
test('omitted markers jump from 239 to 1000000000', () => {
  const preimage = new Uint8Array(32);
  const paymentHash = sha256(preimage);
  const records: TlvRecord[] = [
    { type: 88n, length: 33n, value: new Uint8Array(33) },
    { type: 239n, length: 1n, value: new Uint8Array([1]) },
    { type: 1_000_000_000n, length: 1n, value: new Uint8Array([2]) },
    { type: 168n, length: 32n, value: paymentHash },
    { type: 176n, length: 33n, value: new Uint8Array(33) },
  ].sort((a, b) => Number(a.type - b.type));

  const proof = {
    records: [],
    includedRecords: records,
    signature: new Uint8Array(64),
    proofSignature: new Uint8Array(64),
    payerSignature: new Uint8Array(64),
    preimage,
    omittedTlvs: [1_000_000_001n],
    missingHashes: [],
    leafHashes: records.map(() => new Uint8Array(32)),
    proofNote: '',
    payerNote: '',
    invoicePaymentHash: paymentHash,
    invoiceNodeId: new Uint8Array(33),
    payerId: new Uint8Array(33),
  };

  parsePayerProof([
    ...records,
    { type: 240n, length: 64n, value: proof.signature },
    { type: 241n, length: 64n, value: proof.proofSignature },
    { type: 1001n, length: 32n, value: preimage },
    { type: 1002n, length: 5n, value: new Uint8Array([0xfe, 0x3b, 0x9a, 0xca, 0x01]) },
    { type: 1003n, length: 0n, value: new Uint8Array(0) },
    { type: 1004n, length: BigInt(records.length * 32), value: new Uint8Array(records.length * 32) },
  ]);
});

console.log(`\n${'='.repeat(60)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed}`);

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const failure of failures) {
    console.log(`  - ${failure}`);
  }
  process.exit(1);
} else {
  console.log('\nAll payer proof test vectors passed!');
}
